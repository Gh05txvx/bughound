package jobs

import (
	"context"
	"errors"
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
