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

// fakeStore adalah jobs.Store in-memory untuk menguji persistensi tanpa mengimpor
// paket store (yang mengimpor jobs → akan jadi siklus impor di test paket jobs).
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
			t.Error("task harus menerima run id")
		}
		return Summary{Saved: 2, Scanned: []string{"demo.test"}, Denied: []string{"evil.test — tidak in-scope"}}, nil
	})
	q.Close() // tunggu semua pekerjaan selesai

	if atomic.LoadInt32(&ran) != 1 {
		t.Fatalf("task harus dijalankan sekali, dapat %d", ran)
	}
	run, ok := q.Get(id)
	if !ok {
		t.Fatal("run tak ditemukan")
	}
	if run.Status != Done {
		t.Errorf("status=%s, ingin done", run.Status)
	}
	if run.Summary.Saved != 2 || len(run.Summary.Scanned) != 1 {
		t.Errorf("summary tak sesuai: %+v", run.Summary)
	}
	if run.FinishedAt.IsZero() || run.StartedAt.IsZero() {
		t.Error("StartedAt/FinishedAt harus terisi")
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
		t.Errorf("harus failed dengan err; dapat %+v", run)
	}
}

func TestQueueRecoversPanic(t *testing.T) {
	q := New(1)
	id := q.Enqueue("demo", "x", func(_ context.Context, _ string) (Summary, error) {
		panic("ledakan")
	})
	q.Close()
	run, _ := q.Get(id)
	if run.Status != Failed || run.Err == "" {
		t.Errorf("panic harus jadi Failed; dapat %+v", run)
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
		t.Fatalf("list demo = %d, ingin 2", len(runs))
	}
	if runs[0].ID != b || runs[1].ID != a {
		t.Error("List harus terbaru dulu")
	}
}

func TestQueueGetUnknown(t *testing.T) {
	q := New(1)
	defer q.Close()
	if _, ok := q.Get("tidak-ada"); ok {
		t.Error("run tak dikenal harus ok=false")
	}
}

// blockingTask memberi tanda saat mulai lalu menunggu ctx dibatalkan (meniru
// engine yang dibunuh lewat exec.CommandContext) dan mengembalikan hasil parsial.
func blockingTask(started chan<- struct{}) Task {
	return func(ctx context.Context, _ string) (Summary, error) {
		close(started)
		<-ctx.Done()
		return Summary{Saved: 3}, fmt.Errorf("orchestrator: dibatalkan: %w", ctx.Err())
	}
}

func TestQueueCancelRunning(t *testing.T) {
	q := New(1)
	started := make(chan struct{})
	id := q.Enqueue("demo", "x", blockingTask(started))
	<-started

	if !q.Cancel(id) {
		t.Fatal("Cancel run berjalan harus true")
	}
	if q.Cancel(id) {
		t.Error("Cancel kedua harus false (Stop sudah diminta)")
	}
	q.Close()

	run, _ := q.Get(id)
	if run.Status != Cancelled {
		t.Fatalf("status=%s, ingin cancelled", run.Status)
	}
	if run.Stopping {
		t.Error("Stopping harus padam setelah run final")
	}
	if run.Summary.Saved != 3 {
		t.Errorf("hasil parsial harus dipertahankan, dapat %+v", run.Summary)
	}
	if run.FinishedAt.IsZero() || !strings.Contains(run.Err, "canceled") {
		t.Errorf("FinishedAt & Err harus terisi: %+v", run)
	}
	if n := len(q.cancels); n != 0 {
		t.Errorf("pembatal harus dibersihkan setelah run selesai, sisa %d", n)
	}
}

func TestQueueCancelQueued(t *testing.T) {
	q := New(1) // satu worker: run kedua tertahan antre
	started := make(chan struct{})
	release := make(chan struct{})
	first := q.Enqueue("demo", "1", func(ctx context.Context, _ string) (Summary, error) {
		close(started)
		<-release
		if ctx.Err() != nil {
			t.Error("ctx run lain tak boleh ikut batal")
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
		t.Fatal("Cancel run antre harus true")
	}
	if run, _ := q.Get(second); run.Status != Cancelled || run.FinishedAt.IsZero() {
		t.Errorf("run antre harus langsung cancelled: %+v", run)
	}
	close(release)
	q.Close()

	if atomic.LoadInt32(&ran) != 0 {
		t.Error("run yang dihentikan saat antre tak boleh dijalankan")
	}
	if run, _ := q.Get(second); !run.StartedAt.IsZero() {
		t.Error("run yang tak pernah jalan tak boleh punya StartedAt")
	}
	if run, _ := q.Get(first); run.Status != Done {
		t.Errorf("run lain tak terpengaruh: status=%s", run.Status)
	}
}

func TestQueueCancelNoop(t *testing.T) {
	q := New(1)
	id := q.Enqueue("demo", "x", okTask)
	q.Close()

	if q.Cancel("tidak-ada") {
		t.Error("Cancel id asing harus false")
	}
	if q.Cancel(id) {
		t.Error("Cancel run yang sudah selesai harus false")
	}
	if run, _ := q.Get(id); run.Status != Done {
		t.Errorf("run selesai tak boleh berubah: %s", run.Status)
	}
}

func TestQueueRemove(t *testing.T) {
	q := New(1)
	id := q.Enqueue("demo", "x", okTask)
	q.Close() // run selesai (Done)

	if q.Remove("tidak-ada") {
		t.Error("Remove id asing harus false")
	}
	if !q.Remove(id) {
		t.Fatal("Remove run selesai harus true")
	}
	if _, ok := q.Get(id); ok {
		t.Error("run yang dihapus tak boleh lagi ada")
	}
	if n := len(q.List("")); n != 0 {
		t.Errorf("daftar harus kosong setelah hapus, ada %d", n)
	}
	if q.Remove(id) {
		t.Error("Remove kedua harus false (sudah hilang)")
	}
}

func TestQueueRemoveActiveRefused(t *testing.T) {
	q := New(1)
	started := make(chan struct{})
	id := q.Enqueue("demo", "x", blockingTask(started))
	<-started

	if q.Remove(id) {
		t.Error("Remove run berjalan harus false (hentikan dulu)")
	}
	if _, ok := q.Get(id); !ok {
		t.Error("run berjalan harus tetap terlacak")
	}
	q.Cancel(id)
	q.Close()
	// Setelah dihentikan (Cancelled) baru boleh dihapus.
	if run, _ := q.Get(id); run.Status != Cancelled {
		t.Fatalf("status=%s, ingin cancelled", run.Status)
	}
	if !q.Remove(id) {
		t.Error("Remove run yang sudah dihentikan harus true")
	}
}

// --- Persistensi riwayat run (WithStore) ---

func TestQueuePersistWriteThrough(t *testing.T) {
	fs := newFakeStore()
	q := New(1, WithStore(fs))
	id := q.Enqueue("demo", "scan demo.test", func(_ context.Context, _ string) (Summary, error) {
		return Summary{Saved: 2, Scanned: []string{"demo.test"}}, nil
	})
	q.Close() // tunggu selesai → finish() sudah persist status terminal

	r, ok := fs.get(id)
	if !ok {
		t.Fatal("run harus tersimpan di store")
	}
	if r.Status != Done {
		t.Errorf("status tersimpan=%s, ingin done", r.Status)
	}
	if r.Summary.Saved != 2 || len(r.Summary.Scanned) != 1 {
		t.Errorf("summary tak ikut tersimpan: %+v", r.Summary)
	}
	if r.FinishedAt.IsZero() || r.StartedAt.IsZero() {
		t.Error("StartedAt/FinishedAt harus ikut tersimpan")
	}
}

func TestQueueReloadReconcilesOrphans(t *testing.T) {
	fs := newFakeStore()
	base := time.Now().UTC().Add(-time.Hour)
	// Pra-isi store: satu run selesai + satu yatim (proses lama mati saat Running).
	fs.runs["run_done"] = &Run{ID: "run_done", Program: "demo", Label: "lama", Status: Done,
		EnqueuedAt: base, StartedAt: base, FinishedAt: base.Add(time.Minute), Summary: Summary{Saved: 1}}
	fs.runs["run_orphan"] = &Run{ID: "run_orphan", Program: "demo", Label: "keputus", Status: Running,
		EnqueuedAt: base.Add(time.Minute)}

	q := New(1, WithStore(fs))
	defer q.Close()

	runs := q.List("demo")
	if len(runs) != 2 {
		t.Fatalf("riwayat dimuat = %d, ingin 2", len(runs))
	}
	// Terbaru dulu: orphan (di-enqueue belakangan) lalu done.
	if runs[0].ID != "run_orphan" || runs[1].ID != "run_done" {
		t.Fatalf("urutan muat salah: %s, %s", runs[0].ID, runs[1].ID)
	}
	orphan, _ := q.Get("run_orphan")
	if orphan.Status != Failed {
		t.Errorf("run yatim harus difinalkan Failed, dapat %s", orphan.Status)
	}
	if orphan.Err == "" || orphan.FinishedAt.IsZero() {
		t.Errorf("run yatim harus punya Err + FinishedAt: %+v", orphan)
	}
	// Koreksi harus dipersist (bukan cuma in-memory).
	if saved, _ := fs.get("run_orphan"); saved == nil || saved.Status != Failed {
		t.Errorf("koreksi run yatim harus tersimpan ke store: %+v", saved)
	}
	// Run selesai tak boleh berubah.
	if done, _ := q.Get("run_done"); done.Status != Done || done.Summary.Saved != 1 {
		t.Errorf("run selesai tak boleh tersentuh rekonsiliasi: %+v", done)
	}
}

func TestQueueRemovePersistsDelete(t *testing.T) {
	fs := newFakeStore()
	q := New(1, WithStore(fs))
	id := q.Enqueue("demo", "x", okTask)
	q.Close()
	if !q.Remove(id) {
		t.Fatal("Remove run selesai harus true")
	}
	if _, ok := fs.get(id); ok {
		t.Error("run yang dihapus harus ikut hilang dari store")
	}
}

func TestQueueRemoveByProgram(t *testing.T) {
	fs := newFakeStore()
	q := New(2, WithStore(fs))
	a1 := q.Enqueue("A", "1", okTask)
	a2 := q.Enqueue("A", "2", okTask)
	b1 := q.Enqueue("B", "3", okTask)
	q.Close() // semua Done

	if n := q.RemoveByProgram("A"); n != 2 {
		t.Fatalf("RemoveByProgram(A) = %d, ingin 2", n)
	}
	if _, ok := q.Get(a1); ok {
		t.Error("run A1 harus hilang dari riwayat")
	}
	if _, ok := q.Get(a2); ok {
		t.Error("run A2 harus hilang dari riwayat")
	}
	if _, ok := fs.get(a1); ok {
		t.Error("run A1 harus ikut terhapus dari store")
	}
	if len(q.List("A")) != 0 {
		t.Error("riwayat program A harus kosong")
	}
	if _, ok := q.Get(b1); !ok {
		t.Error("run program lain (B) tak boleh terhapus")
	}
	if fs.len() != 1 {
		t.Errorf("store harus sisa 1 run (B), ada %d", fs.len())
	}
}

func TestQueueNoStoreStillWorks(t *testing.T) {
	// Tanpa WithStore, queue tetap in-memory seperti dulu (tak ada panic/nil deref).
	q := New(1)
	id := q.Enqueue("demo", "x", okTask)
	q.Close()
	if run, _ := q.Get(id); run.Status != Done {
		t.Errorf("tanpa store, run tetap jalan & Done: %+v", run)
	}
}

func TestQueueStopTooLateStaysDone(t *testing.T) {
	q := New(1)
	started := make(chan struct{})
	release := make(chan struct{})
	id := q.Enqueue("demo", "x", func(context.Context, string) (Summary, error) {
		close(started)
		<-release // abaikan ctx: pekerjaan tetap tuntas walau Stop diminta
		return Summary{Saved: 1}, nil
	})
	<-started
	q.Cancel(id)
	close(release)
	q.Close()

	if run, _ := q.Get(id); run.Status != Done || run.Summary.Saved != 1 {
		t.Errorf("task yang tuntas tanpa galat harus tetap done: %+v", run)
	}
}
