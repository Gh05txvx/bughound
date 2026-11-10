package jobs

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
)

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
