// Package jobs menyediakan antrean kerja in-process: scan dijalankan di latar
// belakang oleh worker pool sehingga request web tidak memblok (prinsip PRD:
// "eksekusi scan asinkron lewat job queue agar UI tetap responsif").
//
// Antrean ini sengaja sederhana (in-process, tanpa Redis) sesuai keputusan M0/M1
// untuk tim kecil.
package jobs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Status adalah keadaan sebuah run.
type Status string

const (
	Queued  Status = "queued"
	Running Status = "running"
	Done    Status = "done"
	Failed  Status = "failed"
)

// Summary adalah ringkasan hasil scan yang disimpan di Run. Sengaja generik
// (angka + daftar string) agar paket jobs tak bergantung pada orchestrator.
type Summary struct {
	Discovered int
	Scanned    []string
	Saved      int
	Duplicates int
	Denied     []string // "target — alasan (lapis)"
}

// Run melacak satu pekerjaan scan.
type Run struct {
	ID         string
	Program    string
	Label      string
	Status     Status
	Summary    Summary
	Err        string
	EnqueuedAt time.Time
	StartedAt  time.Time
	FinishedAt time.Time
}

// Task adalah pekerjaan yang dijalankan worker. Menerima ctx milik QUEUE (bukan
// request HTTP) agar scan tetap berjalan setelah response web dikirim.
type Task func(ctx context.Context, runID string) (Summary, error)

type job struct {
	id   string
	task Task
}

// Queue adalah worker pool in-process dengan pelacakan status.
type Queue struct {
	ch   chan job
	base context.Context
	now  func() time.Time

	mu    sync.RWMutex
	runs  map[string]*Run
	order []string

	wg        sync.WaitGroup
	closeOnce sync.Once
}

// New membuat Queue dengan n worker (minimal 1) dan langsung menjalankannya.
func New(workers int) *Queue {
	if workers < 1 {
		workers = 1
	}
	q := &Queue{
		ch:   make(chan job, 256),
		base: context.Background(),
		now:  time.Now,
		runs: map[string]*Run{},
	}
	q.wg.Add(workers)
	for i := 0; i < workers; i++ {
		go q.worker()
	}
	return q
}

func (q *Queue) worker() {
	defer q.wg.Done()
	for j := range q.ch {
		q.update(j.id, func(r *Run) {
			r.Status = Running
			r.StartedAt = q.now().UTC()
		})
		sum, err := runTask(q.base, j)
		q.update(j.id, func(r *Run) {
			r.FinishedAt = q.now().UTC()
			if err != nil {
				r.Status = Failed
				r.Err = err.Error()
			} else {
				r.Status = Done
				r.Summary = sum
			}
		})
	}
}

// runTask menjalankan task dan memulihkan panik menjadi error.
func runTask(ctx context.Context, j job) (sum Summary, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panic saat scan: %v", p)
		}
	}()
	return j.task(ctx, j.id)
}

// Enqueue mendaftarkan pekerjaan dan mengembalikan run id SEKETIKA (tidak
// menunggu pekerjaan selesai).
func (q *Queue) Enqueue(program, label string, task Task) string {
	id := q.newID()
	run := &Run{ID: id, Program: program, Label: label, Status: Queued, EnqueuedAt: q.now().UTC()}
	q.mu.Lock()
	q.runs[id] = run
	q.order = append(q.order, id)
	q.mu.Unlock()
	q.ch <- job{id: id, task: task}
	return id
}

// Get mengembalikan salinan Run.
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

// List mengembalikan run (salinan) untuk sebuah program, terbaru dulu. program
// kosong = semua.
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

// Close menghentikan penerimaan pekerjaan baru dan menunggu pekerjaan yang
// tersisa selesai (menguras antrean). Aman dipanggil berkali-kali.
func (q *Queue) Close() {
	q.closeOnce.Do(func() { close(q.ch) })
	q.wg.Wait()
}

func (q *Queue) update(id string, fn func(*Run)) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if r, ok := q.runs[id]; ok {
		fn(r)
	}
}

func (q *Queue) newID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return "run_" + q.now().UTC().Format("20060102_150405") + "_" + hex.EncodeToString(b[:])
}
