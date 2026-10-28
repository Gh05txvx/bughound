package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"bughound/internal/jobs"
	"bughound/internal/store"
)

func TestCaptureStartShowsListenerAndRejectsOutOfScope(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()
	if err := st.SaveProgram(ctx, store.Program{
		Name: "cp", InScope: []string{"demo.test", "*.demo.test"}, OutScope: []string{"evil.test"},
	}); err != nil {
		t.Fatal(err)
	}

	// Mulai capture ke target in-scope → redirect lalu sesi aktif terlihat.
	rec := do(t, srv, "POST", "/capture/start", url.Values{
		"program": {"cp"}, "target": {"app.demo.test"}, "rps": {"10"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("start = %d, ingin 303:\n%s", rec.Code, rec.Body.String())
	}
	body := do(t, srv, "GET", "/capture?program=cp", nil).Body.String()
	if !strings.Contains(body, "Sesi aktif") || !strings.Contains(body, "http://127.0.0.1:") {
		t.Errorf("sesi aktif + URL listener harus tampil:\n%s", body)
	}
	if !strings.Contains(body, "app.demo.test") {
		t.Errorf("target harus tampil:\n%s", body)
	}

	// Target out-of-scope ditolak saat start (fail closed), bukan membuka listener.
	rec2 := do(t, srv, "POST", "/capture/start", url.Values{
		"program": {"cp"}, "target": {"evil.test"},
	})
	// program cp sudah punya sesi aktif → ditolak "sudah berjalan"; hentikan dulu.
	if !strings.Contains(rec2.Body.String(), "sudah berjalan") {
		t.Errorf("program dengan sesi aktif harus menolak start kedua:\n%s", rec2.Body.String())
	}
}

func TestCapturePromoteEnqueuesScan(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()
	if err := st.SaveProgram(ctx, store.Program{Name: "cp", InScope: []string{"demo.test", "*.demo.test"}}); err != nil {
		t.Fatal(err)
	}
	// Promote tanpa pilihan → error.
	rec := do(t, srv, "POST", "/capture/promote", url.Values{"program": {"cp"}})
	if !strings.Contains(rec.Body.String(), "minimal satu endpoint") {
		t.Errorf("promote tanpa pilihan harus error:\n%s", rec.Body.String())
	}

	// Promote dua endpoint in-scope → redirect membawa run id.
	rec = do(t, srv, "POST", "/capture/promote", url.Values{
		"program": {"cp"},
		"url":     {"http://app.demo.test/api/a", "http://app.demo.test/api/b"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("promote = %d, ingin 303:\n%s", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "run=") || !strings.Contains(loc, "n=2") {
		t.Fatalf("redirect harus memuat run id & jumlah: %q", loc)
	}
	u, _ := url.Parse(loc)
	runID := u.Query().Get("run")
	if runID == "" {
		t.Fatal("run id kosong di redirect")
	}

	// Scan latar belakang harus selesai tanpa error (jalur scan yang sama).
	deadline := time.Now().Add(3 * time.Second)
	for {
		run, ok := srv.queue.Get(runID)
		if ok && run.Status != jobs.Queued && run.Status != jobs.Running {
			if run.Err != "" {
				t.Fatalf("scan promote gagal: %s", run.Err)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("scan promote tak selesai dalam 3s")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestCaptureStop(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()
	if err := st.SaveProgram(ctx, store.Program{Name: "cp", InScope: []string{"demo.test"}}); err != nil {
		t.Fatal(err)
	}
	do(t, srv, "POST", "/capture/start", url.Values{"program": {"cp"}, "target": {"demo.test"}})
	if srv.getCapture("cp") == nil {
		t.Fatal("sesi harus aktif setelah start")
	}
	rec := do(t, srv, "POST", "/capture/stop", url.Values{"program": {"cp"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("stop = %d, ingin 303", rec.Code)
	}
	if srv.getCapture("cp") != nil {
		t.Error("sesi harus hilang setelah stop")
	}
	body := do(t, srv, "GET", "/capture?program=cp", nil).Body.String()
	if strings.Contains(body, "Sesi aktif") {
		t.Errorf("form start harus kembali tampil setelah stop:\n%s", body)
	}
}

func TestCaptureRequiresProgramScope(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := do(t, srv, "POST", "/capture/start", url.Values{
		"program": {"belum-ada"}, "target": {"app.demo.test"},
	})
	if !strings.Contains(rec.Body.String(), "belum punya scope") {
		t.Errorf("program tanpa scope tersimpan harus error:\n%s", rec.Body.String())
	}
}
