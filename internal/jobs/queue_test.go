package jobs

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeStore is an in-memory jobs.Store for testing persistence without
// importing package store (which imports jobs → an import cycle in this
// package's tests).
type fakeStore struct {
	mu      sync.Mutex
	runs    map[string]*Run
	loadErr error
}

func newFakeStore() *fakeStore { return &fakeStore{runs: map[string]*Run{}} }

func (f *fakeStore) LoadRuns(ctx context.Context) ([]*Run, error) {
	if f.loadErr != nil {
		return nil, f.loadErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*Run, 0, len(f.runs))
	for _, r := range f.runs {
		c := *r
		out = append(out, &c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].EnqueuedAt.Before(out[j].EnqueuedAt) })
	return out, nil
}

func (f *fakeStore) SaveRun(ctx context.Context, r *Run) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := *r
	f.runs[r.ID] = &c
	return nil
}

func (f *fakeStore) DeleteRun(ctx context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.runs, id)
	return nil
}

func (f *fakeStore) get(id string) (*Run, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.runs[id]
	if !ok {
		return nil, false
	}
	c := *r
	return &c, true
}

func (f *fakeStore) len() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.runs)
}

func okTask(_ context.Context, _ string) (Summary, error) {
	return Summary{Saved: 1}, nil
}

func TestQueueRunsTask(t *testing.T) {
	q := New(2)
	var ran int32
	id := q.Enqueue("demo", "scan demo.test", func(_ context.Context, runID string) (Summary, error) {
		atomic.AddInt32(&ran, 1)
		if runID == "" {
			t.Error("the task must receive the run id")
		}
		return Summary{Saved: 2, Scanned: []string{"demo.test"}, Denied: []string{"evil.test — not in scope"}}, nil
	})
	q.Close() // wait for every job to finish

	if atomic.LoadInt32(&ran) != 1 {
		t.Fatalf("the task must run once, got %d", ran)
	}
	run, ok := q.Get(id)
	if !ok {
		t.Fatal("run not found")
	}
	if run.Status != Done {
		t.Errorf("status=%s, want done", run.Status)
	}
	if run.Summary.Saved != 2 || len(run.Summary.Scanned) != 1 {
		t.Errorf("unexpected summary: %+v", run.Summary)
	}
	if run.FinishedAt.IsZero() || run.StartedAt.IsZero() {
		t.Error("StartedAt/FinishedAt must be set")
	}
}

func TestQueueFailedTask(t *testing.T) {
	q := New(1)
	id := q.Enqueue("demo", "x", func(_ context.Context, _ string) (Summary, error) {
		return Summary{}, errors.New("boom")
	})
	q.Close()
	run, _ := q.Get(id)
	if run.Status != Failed || run.Err == "" {
		t.Errorf("must be failed with an err; got %+v", run)
	}
}

func TestQueueRecoversPanic(t *testing.T) {
	q := New(1)
	id := q.Enqueue("demo", "x", func(_ context.Context, _ string) (Summary, error) {
		panic("boom")
	})
	q.Close()
	run, _ := q.Get(id)
	if run.Status != Failed || run.Err == "" {
		t.Errorf("a panic must become Failed; got %+v", run)
	}
}

func TestQueueListNewestFirst(t *testing.T) {
	q := New(1)
	a := q.Enqueue("demo", "1", okTask)
	b := q.Enqueue("demo", "2", okTask)
	_ = q.Enqueue("other", "3", okTask)
	q.Close()

	runs := q.List("demo")
	if len(runs) != 2 {
		t.Fatalf("list demo = %d, want 2", len(runs))
	}
	if runs[0].ID != b || runs[1].ID != a {
		t.Error("List must be newest first")
	}
}

func TestQueueGetUnknown(t *testing.T) {
	q := New(1)
	defer q.Close()
	if _, ok := q.Get("missing"); ok {
		t.Error("an unknown run must return ok=false")
	}
}

// blockingTask signals when it starts, then waits for ctx to be cancelled (like
// an engine killed through exec.CommandContext) and returns a partial result.
func blockingTask(started chan<- struct{}) Task {
	return func(ctx context.Context, _ string) (Summary, error) {
		close(started)
		<-ctx.Done()
		return Summary{Saved: 3}, fmt.Errorf("orchestrator: cancelled: %w", ctx.Err())
	}
}

func TestQueueCancelRunning(t *testing.T) {
	q := New(1)
	started := make(chan struct{})
	id := q.Enqueue("demo", "x", blockingTask(started))
	<-started

	if !q.Cancel(id) {
		t.Fatal("Cancel on a running run must be true")
	}
	if q.Cancel(id) {
		t.Error("a second Cancel must be false (Stop was already requested)")
	}
	q.Close()

	run, _ := q.Get(id)
	if run.Status != Cancelled {
		t.Fatalf("status=%s, want cancelled", run.Status)
	}
	if run.Stopping {
		t.Error("Stopping must clear once the run is final")
	}
	if run.Summary.Saved != 3 {
		t.Errorf("the partial result must be kept, got %+v", run.Summary)
	}
	if run.FinishedAt.IsZero() || !strings.Contains(run.Err, "canceled") {
		t.Errorf("FinishedAt and Err must be set: %+v", run)
	}
	if n := len(q.cancels); n != 0 {
		t.Errorf("the cancel func must be cleaned up after the run ends, %d left", n)
	}
}

func TestQueueCancelQueued(t *testing.T) {
	q := New(1) // one worker: the second run waits in the queue
	started := make(chan struct{})
	release := make(chan struct{})
	first := q.Enqueue("demo", "1", func(ctx context.Context, _ string) (Summary, error) {
		close(started)
		<-release
		if ctx.Err() != nil {
			t.Error("another run's ctx must not be cancelled too")
		}
		return Summary{}, nil
	})
	<-started
	var ran int32
	second := q.Enqueue("demo", "2", func(context.Context, string) (Summary, error) {
		atomic.AddInt32(&ran, 1)
		return Summary{}, nil
	})

	if !q.Cancel(second) {
		t.Fatal("Cancel on a queued run must be true")
	}
	if run, _ := q.Get(second); run.Status != Cancelled || run.FinishedAt.IsZero() {
		t.Errorf("a queued run must be cancelled right away: %+v", run)
	}
	close(release)
	q.Close()

	if atomic.LoadInt32(&ran) != 0 {
		t.Error("a run stopped while queued must not run")
	}
	if run, _ := q.Get(second); !run.StartedAt.IsZero() {
		t.Error("a run that never ran must not have a StartedAt")
	}
	if run, _ := q.Get(first); run.Status != Done {
		t.Errorf("the other run must be unaffected: status=%s", run.Status)
	}
}

func TestQueueCancelNoop(t *testing.T) {
	q := New(1)
	id := q.Enqueue("demo", "x", okTask)
	q.Close()

	if q.Cancel("missing") {
		t.Error("Cancel on an unknown id must be false")
	}
	if q.Cancel(id) {
		t.Error("Cancel on a finished run must be false")
	}
	if run, _ := q.Get(id); run.Status != Done {
		t.Errorf("a finished run must not change: %s", run.Status)
	}
}

func TestQueueRemove(t *testing.T) {
	q := New(1)
	id := q.Enqueue("demo", "x", okTask)
	q.Close() // the run is finished (Done)

	if q.Remove("missing") {
		t.Error("Remove on an unknown id must be false")
	}
	if !q.Remove(id) {
		t.Fatal("Remove on a finished run must be true")
	}
	if _, ok := q.Get(id); ok {
		t.Error("a removed run must no longer exist")
	}
	if n := len(q.List("")); n != 0 {
		t.Errorf("the list must be empty after the removal, %d left", n)
	}
	if q.Remove(id) {
		t.Error("a second Remove must be false (already gone)")
	}
}

func TestQueueRemoveActiveRefused(t *testing.T) {
	q := New(1)
	started := make(chan struct{})
	id := q.Enqueue("demo", "x", blockingTask(started))
	<-started

	if q.Remove(id) {
		t.Error("Remove on a running run must be false (stop it first)")
	}
	if _, ok := q.Get(id); !ok {
		t.Error("a running run must stay tracked")
	}
	q.Cancel(id)
	q.Close()
	// Only after it is stopped (Cancelled) may it be removed.
	if run, _ := q.Get(id); run.Status != Cancelled {
		t.Fatalf("status=%s, want cancelled", run.Status)
	}
	if !q.Remove(id) {
		t.Error("Remove on a stopped run must be true")
	}
}

// --- Run history persistence (WithStore) ---

func TestQueuePersistWriteThrough(t *testing.T) {
	fs := newFakeStore()
	q := New(1, WithStore(fs))
	id := q.Enqueue("demo", "scan demo.test", func(_ context.Context, _ string) (Summary, error) {
		return Summary{Saved: 2, Scanned: []string{"demo.test"}}, nil
	})
	q.Close() // wait for it to finish → finish() has persisted the terminal status

	r, ok := fs.get(id)
	if !ok {
		t.Fatal("the run must be saved in the store")
	}
	if r.Status != Done {
		t.Errorf("stored status=%s, want done", r.Status)
	}
	if r.Summary.Saved != 2 || len(r.Summary.Scanned) != 1 {
		t.Errorf("the summary was not saved: %+v", r.Summary)
	}
	if r.FinishedAt.IsZero() || r.StartedAt.IsZero() {
		t.Error("StartedAt/FinishedAt must be saved too")
	}
}

func TestQueueReloadReconcilesOrphans(t *testing.T) {
	fs := newFakeStore()
	base := time.Now().UTC().Add(-time.Hour)
	// Pre-fill the store: one finished run + one orphan (the old process died while it was Running).
	fs.runs["run_done"] = &Run{ID: "run_done", Program: "demo", Label: "old", Status: Done,
		EnqueuedAt: base, StartedAt: base, FinishedAt: base.Add(time.Minute), Summary: Summary{Saved: 1}}
	fs.runs["run_orphan"] = &Run{ID: "run_orphan", Program: "demo", Label: "interrupted", Status: Running,
		EnqueuedAt: base.Add(time.Minute)}

	q := New(1, WithStore(fs))
	defer q.Close()

	runs := q.List("demo")
	if len(runs) != 2 {
		t.Fatalf("history loaded = %d, want 2", len(runs))
	}
	// Newest first: the orphan (enqueued later), then done.
	if runs[0].ID != "run_orphan" || runs[1].ID != "run_done" {
		t.Fatalf("wrong load order: %s, %s", runs[0].ID, runs[1].ID)
	}
	orphan, _ := q.Get("run_orphan")
	if orphan.Status != Failed {
		t.Errorf("the orphan run must be finalized as Failed, got %s", orphan.Status)
	}
	if orphan.Err == "" || orphan.FinishedAt.IsZero() {
		t.Errorf("the orphan run must have Err + FinishedAt: %+v", orphan)
	}
	// The correction must be persisted (not only in memory).
	if saved, _ := fs.get("run_orphan"); saved == nil || saved.Status != Failed {
		t.Errorf("the orphan run's correction must be saved to the store: %+v", saved)
	}
	// The finished run must not change.
	if done, _ := q.Get("run_done"); done.Status != Done || done.Summary.Saved != 1 {
		t.Errorf("reconciliation must not touch the finished run: %+v", done)
	}
}

func TestQueueRemovePersistsDelete(t *testing.T) {
	fs := newFakeStore()
	q := New(1, WithStore(fs))
	id := q.Enqueue("demo", "x", okTask)
	q.Close()
	if !q.Remove(id) {
		t.Fatal("Remove on a finished run must be true")
	}
	if _, ok := fs.get(id); ok {
		t.Error("a removed run must be gone from the store too")
	}
}

func TestQueueRemoveByProgram(t *testing.T) {
	fs := newFakeStore()
	q := New(2, WithStore(fs))
	a1 := q.Enqueue("A", "1", okTask)
	a2 := q.Enqueue("A", "2", okTask)
	b1 := q.Enqueue("B", "3", okTask)
	q.Close() // all Done

	if n := q.RemoveByProgram("A"); n != 2 {
		t.Fatalf("RemoveByProgram(A) = %d, want 2", n)
	}
	if _, ok := q.Get(a1); ok {
		t.Error("run A1 must be gone from the history")
	}
	if _, ok := q.Get(a2); ok {
		t.Error("run A2 must be gone from the history")
	}
	if _, ok := fs.get(a1); ok {
		t.Error("run A1 must be deleted from the store too")
	}
	if len(q.List("A")) != 0 {
		t.Error("program A's history must be empty")
	}
	if _, ok := q.Get(b1); !ok {
		t.Error("another program's run (B) must not be deleted")
	}
	if fs.len() != 1 {
		t.Errorf("the store must have 1 run left (B), has %d", fs.len())
	}
}

func TestQueueNoStoreStillWorks(t *testing.T) {
	// Without WithStore the queue stays in-memory as before (no panic / nil deref).
	q := New(1)
	id := q.Enqueue("demo", "x", okTask)
	q.Close()
	if run, _ := q.Get(id); run.Status != Done {
		t.Errorf("without a store the run still runs and is Done: %+v", run)
	}
}

func TestQueueStopTooLateStaysDone(t *testing.T) {
	q := New(1)
	started := make(chan struct{})
	release := make(chan struct{})
	id := q.Enqueue("demo", "x", func(context.Context, string) (Summary, error) {
		close(started)
		<-release // ignore ctx: the job still completes even though Stop was requested
		return Summary{Saved: 1}, nil
	})
	<-started
	q.Cancel(id)
	close(release)
	q.Close()

	if run, _ := q.Get(id); run.Status != Done || run.Summary.Saved != 1 {
		t.Errorf("a task that completes without an error must stay done: %+v", run)
	}
}
