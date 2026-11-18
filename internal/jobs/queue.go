// Package jobs provides an in-process work queue: scans run in the background
// on a worker pool so web requests do not block (PRD principle: "scans run
// asynchronously through a job queue so the UI stays responsive").
//
// The queue is simple on purpose (in-process, no Redis), following the M0/M1
// decision for a small team.
package jobs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"
)

// Status is the state of a run.
type Status string

const (
	Queued    Status = "queued"
	Running   Status = "running"
	Done      Status = "done"
	Failed    Status = "failed"
	Cancelled Status = "cancelled" // stopped by the user (Stop) before it finished
)

// Summary is the scan result summary stored on a Run. It is generic on purpose
// (numbers + string lists) so package jobs does not depend on the orchestrator.
type Summary struct {
	Discovered int
	Scanned    []string
	Saved      int
	Duplicates int
	Denied     []string // "target — reason (layer)"
	Warnings   []string // e.g. an engine failed on one target (the run still finishes)
}

// Run tracks one scan job.
type Run struct {
	ID      string
	Program string
	Label   string
	Status  Status
	// Stopping: Stop was requested while the run was in progress; its context is
	// already cancelled and the worker is waiting for the task to stop before it
	// finalizes Cancelled.
	Stopping bool
	// Summary is also filled in for failed or stopped runs (partial results).
	Summary    Summary
	Err        string
	EnqueuedAt time.Time
	StartedAt  time.Time
	FinishedAt time.Time
}

// Task is the work a worker runs. It receives a ctx owned by the QUEUE (not by
// the HTTP request) so the scan keeps running after the web response is sent;
// only Cancel(runID) cancels that ctx.
type Task func(ctx context.Context, runID string) (Summary, error)

type job struct {
	id   string
	task Task
}

// Store persists the run history so it survives a process restart or redeploy.
// It is optional: a Queue created without a store stays in-memory only (the old
// behaviour). Implementations (store.SQLite / store.Mem) serialize Run; package
// jobs knows nothing about storage details (a port, not a dependency on store).
type Store interface {
	// LoadRuns returns every stored run, OLDEST first (enqueue order).
	LoadRuns(ctx context.Context) ([]*Run, error)
	// SaveRun saves or overwrites one run (write-through on every status transition).
	SaveRun(ctx context.Context, r *Run) error
	// DeleteRun removes one run from storage.
	DeleteRun(ctx context.Context, id string) error
}

// Option configures a Queue at New.
type Option func(*Queue)

// WithStore makes the Queue persist the run history: write-through on every
// status transition, and a reload at start (orphan runs are finalized as
// Failed). A nil store is a no-op (the queue stays in-memory).
func WithStore(s Store) Option {
	return func(q *Queue) {
		if s != nil {
			q.store = s
		}
	}
}

// Queue is an in-process worker pool with status tracking.
type Queue struct {
	ch    chan job
	base  context.Context
	now   func() time.Time
	store Store // optional: run history persistence (nil = in-memory only)

	mu      sync.RWMutex
	runs    map[string]*Run
	order   []string
	cancels map[string]context.CancelFunc // running run → the cancel func of its context

	wg        sync.WaitGroup
	closeOnce sync.Once
}

// New creates a Queue with n workers (at least 1) and starts them right away.
// With WithStore the run history is persisted and reloaded at start.
func New(workers int, opts ...Option) *Queue {
	if workers < 1 {
		workers = 1
	}
	q := &Queue{
		ch:      make(chan job, 256),
		base:    context.Background(),
		now:     time.Now,
		runs:    map[string]*Run{},
		cancels: map[string]context.CancelFunc{},
	}
	for _, opt := range opts {
		opt(q)
	}
	if q.store != nil {
		q.loadAndReconcile() // before the workers start: safe without the lock
	}
	q.wg.Add(workers)
	for i := 0; i < workers; i++ {
		go q.worker()
	}
	return q
}

// loadAndReconcile loads the stored run history into in-memory tracking at
// start. A run stored as Queued/Running is an ORPHAN: the process that ran it
// is dead (restart/redeploy) and its worker and engine subprocesses are gone.
// It is finalized as Failed with a clear note, and the correction is persisted.
// Called from New before the workers start (no competitors → no lock needed).
func (q *Queue) loadAndReconcile() {
	ctx, cancel := context.WithTimeout(q.base, 10*time.Second)
	defer cancel()
	runs, err := q.store.LoadRuns(ctx)
	if err != nil {
		log.Printf("jobs: loading the run history failed (continuing without it): %v", err)
		return
	}
	for _, r := range runs {
		if r.Status == Queued || r.Status == Running {
			r.Status = Failed
			r.Stopping = false
			if r.Err == "" {
				r.Err = "interrupted when the process stopped (restart/redeploy)"
			}
			if r.FinishedAt.IsZero() {
				r.FinishedAt = q.now().UTC()
			}
			if err := q.store.SaveRun(ctx, r); err != nil {
				log.Printf("jobs: persisting the fix for orphan run %s failed: %v", r.ID, err)
			}
		}
		q.runs[r.ID] = r
		q.order = append(q.order, r.ID)
	}
}

// persist saves a copy of the run to the store (best effort, CALLED OUTSIDE the
// queue lock). Errors are only logged: a durability failure must not fail the
// scan, and the next transition saves the whole run again. Writes for one run
// are always ordered (Enqueue→begin→finish in the same worker goroutine;
// Enqueue persists before sending to the channel), so they cannot overtake
// each other.
func (q *Queue) persist(r *Run) {
	if q.store == nil || r == nil {
		return
	}
	ctx, cancel := context.WithTimeout(q.base, 5*time.Second)
	defer cancel()
	if err := q.store.SaveRun(ctx, r); err != nil {
		log.Printf("jobs: saving run %s failed: %v", r.ID, err)
	}
}

func (q *Queue) deleteFromStore(id string) {
	if q.store == nil {
		return
	}
	ctx, cancel := context.WithTimeout(q.base, 5*time.Second)
	defer cancel()
	if err := q.store.DeleteRun(ctx, id); err != nil {
		log.Printf("jobs: deleting run %s failed: %v", id, err)
	}
}

func (q *Queue) worker() {
	defer q.wg.Done()
	for j := range q.ch {
		ctx, cancel := context.WithCancel(q.base)
		if q.begin(j.id, cancel) {
			sum, err := runTask(ctx, j)
			q.finish(j.id, sum, err)
		}
		cancel()
	}
}

// begin marks the run as running and registers its cancel func. false = the run
// was stopped while queued, so it is not run.
func (q *Queue) begin(id string, cancel context.CancelFunc) bool {
	q.mu.Lock()
	r, ok := q.runs[id]
	if !ok || r.Status != Queued {
		q.mu.Unlock()
		return false
	}
	r.Status = Running
	r.StartedAt = q.now().UTC()
	q.cancels[id] = cancel
	c := *r
	q.mu.Unlock()
	q.persist(&c)
	return true
}

// finish finalizes the run. An error after Stop was requested = Cancelled, not
// Failed; a task that completes even though Stop was requested is still Done.
func (q *Queue) finish(id string, sum Summary, err error) {
	q.mu.Lock()
	delete(q.cancels, id)
	r, ok := q.runs[id]
	if !ok {
		q.mu.Unlock()
		return
	}
	r.FinishedAt = q.now().UTC()
	r.Summary = sum
	switch {
	case err == nil:
		r.Status = Done
	case r.Stopping:
		r.Status = Cancelled
		r.Err = err.Error()
	default:
		r.Status = Failed
		r.Err = err.Error()
	}
	r.Stopping = false
	c := *r
	q.mu.Unlock()
	q.persist(&c)
}

// Cancel stops a run. A queued run becomes Cancelled right away (it never
// runs); a running run is cancelled through its context (exec.CommandContext
// kills the engine subprocesses too) and the worker then finalizes it. It
// returns true only when THIS call did the stopping; false for an unknown run,
// a finished run, or one that is already being stopped (idempotent).
func (q *Queue) Cancel(id string) bool {
	q.mu.Lock()
	r, ok := q.runs[id]
	if !ok {
		q.mu.Unlock()
		return false
	}
	switch {
	case r.Status == Queued:
		r.Status = Cancelled
		r.FinishedAt = q.now().UTC()
		c := *r
		q.mu.Unlock()
		q.persist(&c) // terminal; the worker skips begin() → finish() never runs, so this is the only writer
		return true
	case r.Status == Running && !r.Stopping:
		r.Stopping = true
		if cancel := q.cancels[id]; cancel != nil {
			cancel()
		}
		q.mu.Unlock()
		// The transient "stopping" transition is NOT persisted: finish() saves the
		// terminal status (Cancelled). This avoids a write race with finish()'s persist.
		return true
	}
	q.mu.Unlock()
	return false
}

// Remove drops a run that has ALREADY ENDED (done/failed/cancelled) from the
// in-memory history (the scan progress panel). A queued or running run CANNOT
// be removed (stop it first), so its worker and engine subprocesses are not
// orphaned (invariant: only inactive runs leave tracking). false = unknown run
// or still active. It does not touch the store, findings or audit; it is
// housekeeping for the monitoring list only.
func (q *Queue) Remove(id string) bool {
	q.mu.Lock()
	r, ok := q.runs[id]
	if !ok || r.Status == Queued || r.Status == Running {
		q.mu.Unlock()
		return false
	}
	delete(q.runs, id)
	for i, oid := range q.order {
		if oid == id {
			q.order = append(q.order[:i], q.order[i+1:]...)
			break
		}
	}
	q.mu.Unlock()
	q.deleteFromStore(id)
	return true
}

// RemoveByProgram drops every ENDED run (done/failed/cancelled) of a program
// from the history (in-memory + store). Queued and running runs are skipped
// (same invariant as Remove: do not orphan workers or subprocesses). It is used
// when a program's findings are cleared, so the run history is not left
// orphaned. It returns the number of runs dropped.
func (q *Queue) RemoveByProgram(program string) int {
	q.mu.Lock()
	gone := map[string]bool{}
	for id, r := range q.runs {
		if r.Program == program && r.Status != Queued && r.Status != Running {
			gone[id] = true
		}
	}
	if len(gone) > 0 {
		for id := range gone {
			delete(q.runs, id)
		}
		kept := make([]string, 0, len(q.order))
		for _, id := range q.order {
			if !gone[id] {
				kept = append(kept, id)
			}
		}
		q.order = kept
	}
	q.mu.Unlock()
	for id := range gone {
		q.deleteFromStore(id)
	}
	return len(gone)
}

// runTask runs the task and turns a panic into an error.
func runTask(ctx context.Context, j job) (sum Summary, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panic during scan: %v", p)
		}
	}()
	return j.task(ctx, j.id)
}

// Enqueue registers a job and returns the run id IMMEDIATELY (it does not wait
// for the job to finish).
func (q *Queue) Enqueue(program, label string, task Task) string {
	id := q.newID()
	run := &Run{ID: id, Program: program, Label: label, Status: Queued, EnqueuedAt: q.now().UTC()}
	q.mu.Lock()
	q.runs[id] = run
	q.order = append(q.order, id)
	c := *run
	q.mu.Unlock()
	q.persist(&c) // persist BEFORE sending to the channel → the queued state is durable before a worker can start
	q.ch <- job{id: id, task: task}
	return id
}

// Get returns a copy of the Run.
func (q *Queue) Get(id string) (*Run, bool) {
	q.mu.RLock()
	defer q.mu.RUnlock()
	r, ok := q.runs[id]
	if !ok {
		return nil, false
	}
	c := *r
	return &c, true
}

// List returns the runs (copies) of a program, newest first. An empty program
// means all runs.
func (q *Queue) List(program string) []*Run {
	q.mu.RLock()
	defer q.mu.RUnlock()
	var out []*Run
	for i := len(q.order) - 1; i >= 0; i-- {
		r := q.runs[q.order[i]]
		if program == "" || r.Program == program {
			c := *r
			out = append(out, &c)
		}
	}
	return out
}

// Close stops accepting new jobs and waits for the remaining ones to finish
// (it drains the queue). It is safe to call more than once.
func (q *Queue) Close() {
	q.closeOnce.Do(func() { close(q.ch) })
	q.wg.Wait()
}

func (q *Queue) newID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return "run_" + q.now().UTC().Format("20060102_150405") + "_" + hex.EncodeToString(b[:])
}
