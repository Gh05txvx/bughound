package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"bughound/internal/audit"
	"bughound/internal/engine"
	"bughound/internal/engine/nuclei"
	"bughound/internal/finding"
	"bughound/internal/jobs"
	"bughound/internal/secret"
	"bughound/internal/store"
)

// blockEngine mimics a long-running external engine: Scan waits for the ctx
// to be cancelled, like a subprocess killed by exec.CommandContext. A deadline
// keeps the test from hanging if Stop fails.
type blockEngine struct {
	started  chan struct{}
	once     sync.Once
	canceled atomic.Bool
}

func newBlockEngine() *blockEngine { return &blockEngine{started: make(chan struct{})} }

func (b *blockEngine) Name() string { return "block" }

func (b *blockEngine) Scan(ctx context.Context, _, _, _ string) ([]*finding.Finding, error) {
	b.once.Do(func() { close(b.started) })
	select {
	case <-ctx.Done():
		b.canceled.Store(true)
		return nil, ctx.Err()
	case <-time.After(10 * time.Second):
		return nil, errors.New("blockEngine: never cancelled")
	}
}

// ctxLog mimics the SQLite audit: Append rejects an already-cancelled ctx. Used to
// prove the audit trail of a Stopped run is still recorded.
type ctxLog struct{ audit.Log }

func (l ctxLog) Append(ctx context.Context, e audit.Event) (audit.Event, error) {
	if err := ctx.Err(); err != nil {
		return audit.Event{}, err
	}
	return l.Log.Append(ctx, e)
}

func newStopServer(t *testing.T, eng engine.Engine) (*Server, *store.Mem, audit.Log) {
	t.Helper()
	st := store.NewMem()
	k, _ := secret.NewRandomKey()
	al := audit.NewMemLog([]byte("test-audit-key"))
	srv, err := NewServer(Config{
		Store:        st,
		Engines:      []engine.Engine{eng},
		Vault:        secret.NewMemVault(secret.NewKeyring(k)),
		Audit:        ctxLog{al},
		AuthDisabled: true,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv, st, al
}

func startScan(t *testing.T, srv *Server) string {
	t.Helper()
	rec := do(t, srv, "POST", "/scan", scanForm)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /scan = %d", rec.Code)
	}
	return runIDFrom(t, rec.Body.String())
}

func waitStarted(t *testing.T, b *blockEngine) {
	t.Helper()
	select {
	case <-b.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the engine never started")
	}
}

func waitStatus(t *testing.T, srv *Server, id string, want jobs.Status) *jobs.Run {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if run, ok := srv.queue.Get(id); ok && run.Status == want {
			return run
		}
	}
	run, _ := srv.queue.Get(id)
	t.Fatalf("run %s did not reach %s: %+v", id, want, run)
	return nil
}

func auditOf(t *testing.T, al audit.Log, kind string) []audit.Event {
	t.Helper()
	evs, err := al.List(context.Background(), audit.Filter{Kind: kind})
	if err != nil {
		t.Fatal(err)
	}
	return evs
}

func TestRunStopCancelsRunningScan(t *testing.T) {
	eng := newBlockEngine()
	srv, _, al := newStopServer(t, eng)
	id := startScan(t, srv)
	waitStarted(t, eng)

	rec := do(t, srv, "POST", "/runs/"+id+"/stop", url.Values{})
	if rec.Code != http.StatusOK {
		t.Fatalf("stop = %d", rec.Code)
	}
	if b := rec.Body.String(); !strings.Contains(b, "stopping") && !strings.Contains(b, "stopped") {
		t.Errorf("the stop response must show the run stopped:\n%s", b)
	}
	waitStatus(t, srv, id, jobs.Cancelled)
	if !eng.canceled.Load() {
		t.Error("the engine ctx must be cancelled so the subprocess dies too")
	}

	// A repeated Stop = no-op: still 200, not recorded again.
	if rec := do(t, srv, "POST", "/runs/"+id+"/stop", url.Values{}); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "stopped") {
		t.Errorf("repeated stop = %d, want 200 + stopped status", rec.Code)
	}
	if n := len(auditOf(t, al, "run.stop")); n != 1 {
		t.Errorf("run.stop recorded %d times, want 1", n)
	}
	// run.finish is still recorded even though the run's ctx is already cancelled.
	if fin := auditOf(t, al, "run.finish"); len(fin) != 1 || !strings.HasPrefix(fin[0].Message, "stopped") {
		t.Errorf("run.finish must be recorded as stopped: %+v", fin)
	}
}

func TestRunStopFromDashboard(t *testing.T) {
	eng := newBlockEngine()
	srv, _, _ := newStopServer(t, eng)
	id := startScan(t, srv)
	waitStarted(t, eng)

	stopBtn := `hx-post="/runs/` + id + `/stop?view=dashboard"`
	rerunBtn := `hx-post="/runs/` + id + `/rerun?view=dashboard"`
	if panel := do(t, srv, "GET", "/dashboard/scans", nil).Body.String(); !strings.Contains(panel, stopBtn) || strings.Contains(panel, rerunBtn) {
		t.Fatalf("a running run: must have Stop, no Rerun yet:\n%s", panel)
	}
	// Rerun is denied while the run is still running.
	if b := do(t, srv, "POST", "/runs/"+id+"/rerun?view=dashboard", url.Values{}).Body.String(); !strings.Contains(b, "still running") {
		t.Errorf("rerun while running must be denied:\n%s", b)
	}
	if n := len(srv.queue.List("")); n != 1 {
		t.Fatalf("there must be no new run, there are %d", n)
	}

	rec := do(t, srv, "POST", "/runs/"+id+"/stop?view=dashboard", url.Values{})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `id="live-scans"`) {
		t.Fatalf("stop from the dashboard must reply with the panel: %d\n%s", rec.Code, rec.Body.String())
	}
	waitStatus(t, srv, id, jobs.Cancelled)

	panel := do(t, srv, "GET", "/dashboard/scans", nil).Body.String()
	if !strings.Contains(panel, "stopped") || !strings.Contains(panel, rerunBtn) || strings.Contains(panel, stopBtn) {
		t.Errorf("a stopped run: must be labeled stopped, have Rerun, no Stop:\n%s", panel)
	}
}

func TestRunStopFinishedIsNoop(t *testing.T) {
	srv, _, al := newStopServer(t, nuclei.Mock{})
	id := startScan(t, srv)
	waitStatus(t, srv, id, jobs.Done)

	rec := do(t, srv, "POST", "/runs/"+id+"/stop", url.Values{})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "View findings") {
		t.Fatalf("stop a finished run = %d, want 200 + finished status:\n%s", rec.Code, rec.Body.String())
	}
	if run, _ := srv.queue.Get(id); run.Status != jobs.Done {
		t.Errorf("a finished run must not change: %s", run.Status)
	}
	if n := len(auditOf(t, al, "run.stop")); n != 0 {
		t.Errorf("a no-op stop must not be audited, there are %d", n)
	}
	if rec := do(t, srv, "POST", "/runs/does-not-exist/stop", url.Values{}); rec.Code != http.StatusNotFound {
		t.Errorf("stop an unknown run = %d, want 404", rec.Code)
	}
}

func TestRunDeleteFromDashboard(t *testing.T) {
	srv, _, al := newStopServer(t, nuclei.Mock{})
	id := startScan(t, srv)
	waitStatus(t, srv, id, jobs.Done)

	delBtn := `hx-post="/runs/` + id + `/delete?view=dashboard"`
	if panel := do(t, srv, "GET", "/dashboard/scans", nil).Body.String(); !strings.Contains(panel, delBtn) {
		t.Fatalf("a finished run must have a Delete button:\n%s", panel)
	}

	rec := do(t, srv, "POST", "/runs/"+id+"/delete?view=dashboard", url.Values{})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `id="live-scans"`) {
		t.Fatalf("delete must reply with the panel: %d\n%s", rec.Code, rec.Body.String())
	}
	if _, ok := srv.queue.Get(id); ok {
		t.Error("a deleted run must no longer be in the queue")
	}
	if strings.Contains(rec.Body.String(), id) {
		t.Error("the panel must no longer show the deleted run")
	}
	if _, ok := srv.specFor(id); ok {
		t.Error("the rerun spec must be dropped too")
	}
	if ev := auditOf(t, al, "run.delete"); len(ev) != 1 || !ev[0].Allowed || ev[0].RunID != id {
		t.Errorf("delete must be audited for that run: %+v", ev)
	}
	// Deleting an already-gone run = still 200, not audited again.
	if rec := do(t, srv, "POST", "/runs/"+id+"/delete?view=dashboard", url.Values{}); rec.Code != http.StatusOK {
		t.Errorf("delete an already-gone run = %d, want 200", rec.Code)
	}
	if n := len(auditOf(t, al, "run.delete")); n != 1 {
		t.Errorf("run.delete recorded %d times, want 1", n)
	}
}

func TestRunDeleteActiveRefused(t *testing.T) {
	eng := newBlockEngine()
	srv, _, al := newStopServer(t, eng)
	id := startScan(t, srv)
	waitStarted(t, eng)

	// A running run: no Delete button, and the POST is denied with a message.
	if panel := do(t, srv, "GET", "/dashboard/scans", nil).Body.String(); strings.Contains(panel, "/delete?view=dashboard") {
		t.Error("a running run must not have a Delete button")
	}
	rec := do(t, srv, "POST", "/runs/"+id+"/delete?view=dashboard", url.Values{})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Stop it first") {
		t.Fatalf("deleting a running run must be denied with a message:\n%s", rec.Body.String())
	}
	if _, ok := srv.queue.Get(id); !ok {
		t.Error("the running run must stay")
	}
	if n := len(auditOf(t, al, "run.delete")); n != 0 {
		t.Errorf("a denied delete must not be audited, there are %d", n)
	}
	// Clean up so Close() in cleanup does not hang waiting for the engine.
	do(t, srv, "POST", "/runs/"+id+"/stop", url.Values{})
	waitStatus(t, srv, id, jobs.Cancelled)
}

func TestRunRerunUsesCurrentScope(t *testing.T) {
	srv, st, al := newStopServer(t, nuclei.Mock{})
	id := startScan(t, srv)
	if first := waitStatus(t, srv, id, jobs.Done); len(first.Summary.Scanned) != 1 {
		t.Fatalf("the original run must scan demo.test: %+v", first.Summary)
	}
	// The scope is narrowed after the original run: the rerun must use the current scope.
	if err := st.SaveProgram(context.Background(), store.Program{Name: "demo", InScope: []string{"other.test"}}); err != nil {
		t.Fatal(err)
	}

	rec := do(t, srv, "POST", "/runs/"+id+"/rerun?view=dashboard", url.Values{})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `id="live-scans"`) {
		t.Fatalf("rerun must reply with the panel: %d", rec.Code)
	}
	runs := srv.queue.List("demo")
	if len(runs) != 2 {
		t.Fatalf("rerun must add one run, there are %d", len(runs))
	}
	again := waitStatus(t, srv, runs[0].ID, jobs.Done)
	if len(again.Summary.Scanned) != 0 || len(again.Summary.Denied) == 0 {
		t.Errorf("a target now out of scope must be denied by the guard: %+v", again.Summary)
	}
	if ev := auditOf(t, al, "run.rerun"); len(ev) != 1 || !ev[0].Allowed || ev[0].RunID != again.ID {
		t.Errorf("rerun must be audited for the new run: %+v", ev)
	}
}

func TestRunRerunRefusedWithoutProgram(t *testing.T) {
	srv, st, al := newStopServer(t, nuclei.Mock{})
	id := startScan(t, srv)
	waitStatus(t, srv, id, jobs.Done)
	if err := st.DeleteProgram(context.Background(), "demo"); err != nil {
		t.Fatal(err)
	}

	rec := do(t, srv, "POST", "/runs/"+id+"/rerun?view=dashboard", url.Values{})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Rerun denied") {
		t.Fatalf("rerun without a program must be denied:\n%s", rec.Body.String())
	}
	if n := len(srv.queue.List("")); n != 1 {
		t.Errorf("a denial must not add a run, there are %d", n)
	}
	if ev := auditOf(t, al, "run.rerun"); len(ev) != 1 || ev[0].Allowed {
		t.Errorf("a rerun denial must be audited Allowed=false: %+v", ev)
	}
}

func TestRunControlsRBAC(t *testing.T) {
	srv, _ := newRBACServer(t)
	oc, osess := loginAs(t, srv, "oper", "operpw")
	id := runIDFrom(t, authedReq(srv, "POST", "/scan", scanForm, oc, osess).Body.String())
	waitStatus(t, srv, id, jobs.Done)

	vc, vsess := loginAs(t, srv, "view", "viewpw")
	for _, path := range []string{"/runs/" + id + "/stop", "/runs/" + id + "/rerun", "/runs/" + id + "/delete"} {
		if rec := authedReq(srv, "POST", path, url.Values{}, vc, vsess); rec.Code != http.StatusForbidden {
			t.Errorf("viewer POST %s = %d, want 403", path, rec.Code)
		}
	}
	if b := authedReq(srv, "GET", "/dashboard/scans", nil, vc, vsess).Body.String(); strings.Contains(b, "/rerun") || strings.Contains(b, "/stop") || strings.Contains(b, "/delete") {
		t.Error("the viewer panel must not hold Stop/Rerun/Delete buttons")
	}
	if b := authedReq(srv, "GET", "/dashboard/scans", nil, oc, osess).Body.String(); !strings.Contains(b, "/runs/"+id+"/rerun") || !strings.Contains(b, "/runs/"+id+"/delete") {
		t.Error("the operator panel must hold Rerun & Delete buttons")
	}
	if rec := authedReq(srv, "POST", "/runs/"+id+"/rerun?view=dashboard", url.Values{}, oc, osess); rec.Code != http.StatusOK {
		t.Errorf("operator rerun = %d, want 200", rec.Code)
	}
}

func TestScanSpecRedacted(t *testing.T) {
	sp := scanSpec{proxyChain: []string{"socks5://user:s3cr3t@10.0.0.1:1080"}, targets: []string{"demo.test"}}
	for _, f := range []string{"%v", "%+v", "%#v", "%s"} {
		if out := fmt.Sprintf(f, sp); strings.Contains(out, "s3cr3t") {
			t.Errorf("format %s leaks the proxy credential: %s", f, out)
		}
	}
}

func TestRememberSpecBounded(t *testing.T) {
	srv, _ := newTestServer(t)
	for i := range rerunKeep + 5 {
		srv.rememberSpec(fmt.Sprintf("run%d", i), scanSpec{})
	}
	if _, ok := srv.specFor("run0"); ok {
		t.Error("the oldest spec must be dropped")
	}
	if _, ok := srv.specFor(fmt.Sprintf("run%d", rerunKeep+4)); !ok {
		t.Error("the newest spec must be present")
	}
	if n := len(srv.specs); n != rerunKeep {
		t.Errorf("specs remembered %d, want %d", n, rerunKeep)
	}
}
