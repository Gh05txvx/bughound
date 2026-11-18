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

	// Start a capture to an in-scope target → redirect, then the active session is visible.
	rec := do(t, srv, "POST", "/capture/start", url.Values{
		"program": {"cp"}, "target": {"app.demo.test"}, "rps": {"10"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("start = %d, want 303:\n%s", rec.Code, rec.Body.String())
	}
	body := do(t, srv, "GET", "/capture?program=cp", nil).Body.String()
	if !strings.Contains(body, "Active session") || !strings.Contains(body, "http://127.0.0.1:") {
		t.Errorf("the active session + listener URL must show:\n%s", body)
	}
	if !strings.Contains(body, "app.demo.test") {
		t.Errorf("the target must show:\n%s", body)
	}

	// An out-of-scope target is denied at start (fail closed), not opening a listener.
	rec2 := do(t, srv, "POST", "/capture/start", url.Values{
		"program": {"cp"}, "target": {"evil.test"},
	})
	// program cp already has an active session → denied "already running"; stop it first.
	if !strings.Contains(rec2.Body.String(), "already running") {
		t.Errorf("a program with an active session must reject a second start:\n%s", rec2.Body.String())
	}
}

func TestCapturePromoteEnqueuesScan(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()
	if err := st.SaveProgram(ctx, store.Program{Name: "cp", InScope: []string{"demo.test", "*.demo.test"}}); err != nil {
		t.Fatal(err)
	}
	// Promote with no selection → error.
	rec := do(t, srv, "POST", "/capture/promote", url.Values{"program": {"cp"}})
	if !strings.Contains(rec.Body.String(), "at least one endpoint") {
		t.Errorf("promote with no selection must error:\n%s", rec.Body.String())
	}

	// Promote two in-scope endpoints → the redirect carries a run id.
	rec = do(t, srv, "POST", "/capture/promote", url.Values{
		"program": {"cp"},
		"url":     {"http://app.demo.test/api/a", "http://app.demo.test/api/b"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("promote = %d, want 303:\n%s", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "run=") || !strings.Contains(loc, "n=2") {
		t.Fatalf("the redirect must carry a run id & count: %q", loc)
	}
	u, _ := url.Parse(loc)
	runID := u.Query().Get("run")
	if runID == "" {
		t.Fatal("empty run id in the redirect")
	}

	// The background scan must finish without error (the same scan path).
	deadline := time.Now().Add(3 * time.Second)
	for {
		run, ok := srv.queue.Get(runID)
		if ok && run.Status != jobs.Queued && run.Status != jobs.Running {
			if run.Err != "" {
				t.Fatalf("the promote scan failed: %s", run.Err)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the promote scan did not finish within 3s")
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
		t.Fatal("the session must be active after start")
	}
	rec := do(t, srv, "POST", "/capture/stop", url.Values{"program": {"cp"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("stop = %d, want 303", rec.Code)
	}
	if srv.getCapture("cp") != nil {
		t.Error("the session must be gone after stop")
	}
	body := do(t, srv, "GET", "/capture?program=cp", nil).Body.String()
	if strings.Contains(body, "Active session") {
		t.Errorf("the start form must show again after stop:\n%s", body)
	}
}

func TestCaptureRequiresProgramScope(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := do(t, srv, "POST", "/capture/start", url.Values{
		"program": {"missing"}, "target": {"app.demo.test"},
	})
	if !strings.Contains(rec.Body.String(), "no saved scope") {
		t.Errorf("a program with no saved scope must error:\n%s", rec.Body.String())
	}
}
