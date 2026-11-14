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
	"log"
	"sync"
	"time"
)

// Status adalah keadaan sebuah run.
type Status string

const (
	Queued    Status = "queued"
	Running   Status = "running"
	Done      Status = "done"
	Failed    Status = "failed"
	Cancelled Status = "cancelled" // dihentikan pengguna (Stop) sebelum selesai
)

// Summary adalah ringkasan hasil scan yang disimpan di Run. Sengaja generik
// (angka + daftar string) agar paket jobs tak bergantung pada orchestrator.
type Summary struct {
	Discovered int
	Scanned    []string
	Saved      int
	Duplicates int
	Denied     []string // "target — alasan (lapis)"
	Warnings   []string // mis. engine gagal di satu target (run tetap selesai)
}

// Run melacak satu pekerjaan scan.
type Run struct {
	ID      string
	Program string
	Label   string
	Status  Status
	// Stopping: Stop diminta saat run berjalan; context-nya sudah dibatalkan
	// dan worker menunggu task berhenti sebelum memfinalkan Cancelled.
	Stopping bool
	// Summary juga terisi pada run gagal/dihentikan (hasil parsial).
	Summary    Summary
	Err        string
	EnqueuedAt time.Time
	StartedAt  time.Time
	FinishedAt time.Time
}

// Task adalah pekerjaan yang dijalankan worker. Menerima ctx milik QUEUE (bukan
// request HTTP) agar scan tetap berjalan setelah response web dikirim; ctx itu
// dibatalkan hanya oleh Cancel(runID).
type Task func(ctx context.Context, runID string) (Summary, error)

type job struct {
	id   string
	task Task
}

// Store mempersistenkan riwayat run agar selamat dari restart/redeploy proses.
// Opsional: bila Queue dibuat tanpa store, ia tetap murni in-memory (perilaku
// lama). Implementasi (store.SQLite / store.Mem) menyerialkan Run; paket jobs
// tetap tak tahu detail penyimpanan (port, bukan dependensi ke store).
type Store interface {
	// LoadRuns mengembalikan semua run tersimpan, TERLAMA dulu (urutan enqueue).
	LoadRuns(ctx context.Context) ([]*Run, error)
	// SaveRun menyimpan/menimpa satu run (write-through tiap transisi status).
	SaveRun(ctx context.Context, r *Run) error
	// DeleteRun menghapus satu run dari penyimpanan.
	DeleteRun(ctx context.Context, id string) error
}

// Option mengonfigurasi Queue saat New.
type Option func(*Queue)

// WithStore membuat Queue mempersistenkan riwayat run: write-through tiap
// transisi status + memuat ulang saat start (run yatim difinalkan Failed).
// store nil = no-op (tetap in-memory).
func WithStore(s Store) Option {
	return func(q *Queue) {
		if s != nil {
			q.store = s
		}
	}
}

// Queue adalah worker pool in-process dengan pelacakan status.
type Queue struct {
	ch    chan job
	base  context.Context
	now   func() time.Time
	store Store // opsional: persistensi riwayat run (nil = in-memory saja)

	mu      sync.RWMutex
	runs    map[string]*Run
	order   []string
	cancels map[string]context.CancelFunc // run berjalan → pembatal context-nya

	wg        sync.WaitGroup
	closeOnce sync.Once
}

// New membuat Queue dengan n worker (minimal 1) dan langsung menjalankannya.
// Dengan WithStore, riwayat run dipersist & dimuat ulang saat start.
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
		q.loadAndReconcile() // sebelum worker jalan: aman tanpa lock
	}
	q.wg.Add(workers)
	for i := 0; i < workers; i++ {
		go q.worker()
	}
	return q
}

// loadAndReconcile memuat riwayat run tersimpan ke pelacakan in-memory saat start.
// Run yang tersimpan sebagai Queued/Running adalah YATIM — proses yang
// menjalankannya sudah mati (restart/redeploy), worker & subprocess engine-nya
// hilang — jadi difinalkan Failed dengan catatan jelas dan koreksinya dipersist.
// Dipanggil dari New sebelum worker start (tanpa pesaing → tak perlu lock).
func (q *Queue) loadAndReconcile() {
	ctx, cancel := context.WithTimeout(q.base, 10*time.Second)
	defer cancel()
	runs, err := q.store.LoadRuns(ctx)
	if err != nil {
		log.Printf("jobs: muat riwayat run gagal (lanjut tanpa riwayat): %v", err)
		return
	}
	for _, r := range runs {
		if r.Status == Queued || r.Status == Running {
			r.Status = Failed
			r.Stopping = false
			if r.Err == "" {
				r.Err = "terputus saat proses berhenti (restart/redeploy)"
			}
			if r.FinishedAt.IsZero() {
				r.FinishedAt = q.now().UTC()
			}
			if err := q.store.SaveRun(ctx, r); err != nil {
				log.Printf("jobs: koreksi run yatim %s gagal dipersist: %v", r.ID, err)
			}
		}
		q.runs[r.ID] = r
		q.order = append(q.order, r.ID)
	}
}

// persist menyimpan salinan run ke store (best-effort, DIPANGGIL DI LUAR lock
// queue). Galat hanya di-log: kegagalan durabilitas tak boleh menggagalkan scan,
// dan transisi berikutnya menyimpan ulang run utuh. Penulis per-run selalu
// terurut (Enqueue→begin→finish dalam goroutine worker yang sama; Enqueue persist
// sebelum kirim ke channel) sehingga tulisan tak saling mendahului.
func (q *Queue) persist(r *Run) {
	if q.store == nil || r == nil {
		return
	}
	ctx, cancel := context.WithTimeout(q.base, 5*time.Second)
	defer cancel()
	if err := q.store.SaveRun(ctx, r); err != nil {
		log.Printf("jobs: simpan run %s gagal: %v", r.ID, err)
	}
}

func (q *Queue) deleteFromStore(id string) {
	if q.store == nil {
		return
	}
	ctx, cancel := context.WithTimeout(q.base, 5*time.Second)
	defer cancel()
	if err := q.store.DeleteRun(ctx, id); err != nil {
		log.Printf("jobs: hapus run %s gagal: %v", id, err)
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

// begin menandai run berjalan dan mendaftarkan pembatalnya. false = run sudah
// dihentikan selagi antre, jadi tak dijalankan.
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

// finish memfinalkan run. Galat setelah Stop diminta = Cancelled, bukan Failed;
// task yang tetap tuntas walau Stop diminta tetap Done.
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

// Cancel menghentikan run. Run antre langsung Cancelled (tak pernah jalan); run
// berjalan dibatalkan lewat context-nya (subprocess engine ikut dibunuh
// exec.CommandContext) lalu difinalkan worker. true hanya bila panggilan INI
// yang menghentikan; false untuk run tak dikenal, sudah selesai, atau sudah
// sedang dihentikan (idempoten).
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
		q.persist(&c) // terminal; worker melewati begin() → finish() tak jalan, ini satu-satunya penulis
		return true
	case r.Status == Running && !r.Stopping:
		r.Stopping = true
		if cancel := q.cancels[id]; cancel != nil {
			cancel()
		}
		q.mu.Unlock()
		// Transisi "stopping" transient TIDAK dipersist: finish() yang menyimpan
		// status terminal (Cancelled). Menghindari balapan tulis dgn persist finish().
		return true
	}
	q.mu.Unlock()
	return false
}

// Remove membuang run yang SUDAH BERAKHIR (done/failed/cancelled) dari riwayat
// in-memory (panel Proses scanning). Run antre/berjalan TAK bisa dihapus — Stop
// dulu — agar worker & subprocess engine tak jadi yatim (invarian: hanya run
// non-aktif yang hilang dari pelacakan). false = run tak dikenal atau masih aktif.
// Tak menyentuh store/temuan/audit; murni housekeeping daftar pemantauan.
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

// RemoveByProgram membuang semua run BERAKHIR (done/failed/cancelled) milik sebuah
// program dari riwayat (in-memory + store). Run antre/berjalan dilewati (invarian
// sama dgn Remove: jangan yatimkan worker/subprocess). Dipakai saat temuan program
// dibersihkan agar riwayat run tak jadi yatim. Mengembalikan jumlah yang dibuang.
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
	c := *run
	q.mu.Unlock()
	q.persist(&c) // persist SEBELUM kirim ke channel → state queued durable sebelum worker bisa memulai
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

func (q *Queue) newID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return "run_" + q.now().UTC().Format("20060102_150405") + "_" + hex.EncodeToString(b[:])
}
