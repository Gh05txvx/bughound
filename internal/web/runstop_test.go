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

// blockEngine meniru engine eksternal yang lama berjalan: Scan menunggu ctx
// dibatalkan, seperti subprocess yang dibunuh exec.CommandContext. Batas waktu
// menjaga test tak menggantung bila Stop gagal.
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
		return nil, errors.New("blockEngine: tak pernah dibatalkan")
	}
}

// ctxLog meniru audit SQLite: Append menolak ctx yang sudah batal. Dipakai untuk
// membuktikan jejak audit run yang di-Stop tetap tercatat.
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
		t.Fatal("engine tak pernah mulai")
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
	t.Fatalf("run %s tak mencapai %s: %+v", id, want, run)
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
	if b := rec.Body.String(); !strings.Contains(b, "menghentikan") && !strings.Contains(b, "dihentikan") {
		t.Errorf("respons stop harus menunjukkan run dihentikan:\n%s", b)
	}
	waitStatus(t, srv, id, jobs.Cancelled)
	if !eng.canceled.Load() {
		t.Error("ctx engine harus dibatalkan agar subprocess ikut mati")
	}

	// Stop berulang = no-op: tetap 200, tak dicatat ulang.
	if rec := do(t, srv, "POST", "/runs/"+id+"/stop", url.Values{}); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "dihentikan") {
		t.Errorf("stop ulang = %d, ingin 200 + status dihentikan", rec.Code)
	}
	if n := len(auditOf(t, al, "run.stop")); n != 1 {
		t.Errorf("run.stop tercatat %d kali, ingin 1", n)
	}
	// run.finish tetap tercatat walau ctx run sudah batal.
	if fin := auditOf(t, al, "run.finish"); len(fin) != 1 || !strings.HasPrefix(fin[0].Message, "dihentikan") {
		t.Errorf("run.finish harus tercatat sebagai dihentikan: %+v", fin)
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
		t.Fatalf("run berjalan: harus ada Stop, belum ada Run ulang:\n%s", panel)
	}
	// Run ulang ditolak selama run masih berjalan.
	if b := do(t, srv, "POST", "/runs/"+id+"/rerun?view=dashboard", url.Values{}).Body.String(); !strings.Contains(b, "masih berjalan") {
		t.Errorf("run ulang saat berjalan harus ditolak:\n%s", b)
	}
	if n := len(srv.queue.List("")); n != 1 {
		t.Fatalf("tak boleh ada run baru, ada %d", n)
	}

	rec := do(t, srv, "POST", "/runs/"+id+"/stop?view=dashboard", url.Values{})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `id="live-scans"`) {
		t.Fatalf("stop dari dashboard harus membalas panel: %d\n%s", rec.Code, rec.Body.String())
	}
	waitStatus(t, srv, id, jobs.Cancelled)

	panel := do(t, srv, "GET", "/dashboard/scans", nil).Body.String()
	if !strings.Contains(panel, "dihentikan") || !strings.Contains(panel, rerunBtn) || strings.Contains(panel, stopBtn) {
		t.Errorf("run dihentikan: harus berlabel dihentikan, ada Run ulang, tanpa Stop:\n%s", panel)
	}
}

func TestRunStopFinishedIsNoop(t *testing.T) {
	srv, _, al := newStopServer(t, nuclei.Mock{})
	id := startScan(t, srv)
	waitStatus(t, srv, id, jobs.Done)

	rec := do(t, srv, "POST", "/runs/"+id+"/stop", url.Values{})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Lihat findings") {
		t.Fatalf("stop run selesai = %d, ingin 200 + status selesai:\n%s", rec.Code, rec.Body.String())
	}
	if run, _ := srv.queue.Get(id); run.Status != jobs.Done {
		t.Errorf("run selesai tak boleh berubah: %s", run.Status)
	}
	if n := len(auditOf(t, al, "run.stop")); n != 0 {
		t.Errorf("stop no-op tak boleh diaudit, ada %d", n)
	}
	if rec := do(t, srv, "POST", "/runs/tidak-ada/stop", url.Values{}); rec.Code != http.StatusNotFound {
		t.Errorf("stop run asing = %d, ingin 404", rec.Code)
	}
}

func TestRunDeleteFromDashboard(t *testing.T) {
	srv, _, al := newStopServer(t, nuclei.Mock{})
	id := startScan(t, srv)
	waitStatus(t, srv, id, jobs.Done)

	delBtn := `hx-post="/runs/` + id + `/delete?view=dashboard"`
	if panel := do(t, srv, "GET", "/dashboard/scans", nil).Body.String(); !strings.Contains(panel, delBtn) {
		t.Fatalf("run selesai harus punya tombol Hapus:\n%s", panel)
	}

	rec := do(t, srv, "POST", "/runs/"+id+"/delete?view=dashboard", url.Values{})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `id="live-scans"`) {
		t.Fatalf("hapus harus membalas panel: %d\n%s", rec.Code, rec.Body.String())
	}
	if _, ok := srv.queue.Get(id); ok {
		t.Error("run yang dihapus tak boleh lagi ada di queue")
	}
	if strings.Contains(rec.Body.String(), id) {
		t.Error("panel tak boleh lagi menampilkan run yang dihapus")
	}
	if _, ok := srv.specFor(id); ok {
		t.Error("spec run-ulang harus ikut dibuang")
	}
	if ev := auditOf(t, al, "run.delete"); len(ev) != 1 || !ev[0].Allowed || ev[0].RunID != id {
		t.Errorf("hapus harus diaudit untuk run itu: %+v", ev)
	}
	// Hapus run yang sudah hilang = tetap 200, tak diaudit ulang.
	if rec := do(t, srv, "POST", "/runs/"+id+"/delete?view=dashboard", url.Values{}); rec.Code != http.StatusOK {
		t.Errorf("hapus run yang sudah hilang = %d, ingin 200", rec.Code)
	}
	if n := len(auditOf(t, al, "run.delete")); n != 1 {
		t.Errorf("run.delete tercatat %d kali, ingin 1", n)
	}
}

func TestRunDeleteActiveRefused(t *testing.T) {
	eng := newBlockEngine()
	srv, _, al := newStopServer(t, eng)
	id := startScan(t, srv)
	waitStarted(t, eng)

	// Run berjalan: tak ada tombol Hapus, dan POST ditolak dengan pesan.
	if panel := do(t, srv, "GET", "/dashboard/scans", nil).Body.String(); strings.Contains(panel, "/delete?view=dashboard") {
		t.Error("run berjalan tak boleh punya tombol Hapus")
	}
	rec := do(t, srv, "POST", "/runs/"+id+"/delete?view=dashboard", url.Values{})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Hentikan dulu") {
		t.Fatalf("hapus run berjalan harus ditolak dgn pesan:\n%s", rec.Body.String())
	}
	if _, ok := srv.queue.Get(id); !ok {
		t.Error("run berjalan harus tetap ada")
	}
	if n := len(auditOf(t, al, "run.delete")); n != 0 {
		t.Errorf("hapus yang ditolak tak boleh diaudit, ada %d", n)
	}
	// Bereskan agar Close() di cleanup tak menggantung menunggu engine.
	do(t, srv, "POST", "/runs/"+id+"/stop", url.Values{})
	waitStatus(t, srv, id, jobs.Cancelled)
}

func TestRunRerunUsesCurrentScope(t *testing.T) {
	srv, st, al := newStopServer(t, nuclei.Mock{})
	id := startScan(t, srv)
	if first := waitStatus(t, srv, id, jobs.Done); len(first.Summary.Scanned) != 1 {
		t.Fatalf("run asal harus memindai demo.test: %+v", first.Summary)
	}
	// Scope dipersempit setelah run asal: run ulang wajib memakai scope terkini.
	if err := st.SaveProgram(context.Background(), store.Program{Name: "demo", InScope: []string{"other.test"}}); err != nil {
		t.Fatal(err)
	}

	rec := do(t, srv, "POST", "/runs/"+id+"/rerun?view=dashboard", url.Values{})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `id="live-scans"`) {
		t.Fatalf("run ulang harus membalas panel: %d", rec.Code)
	}
	runs := srv.queue.List("demo")
	if len(runs) != 2 {
		t.Fatalf("run ulang harus menambah satu run, ada %d", len(runs))
	}
	again := waitStatus(t, srv, runs[0].ID, jobs.Done)
	if len(again.Summary.Scanned) != 0 || len(again.Summary.Denied) == 0 {
		t.Errorf("target yang kini di luar scope harus ditolak guard: %+v", again.Summary)
	}
	if ev := auditOf(t, al, "run.rerun"); len(ev) != 1 || !ev[0].Allowed || ev[0].RunID != again.ID {
		t.Errorf("run ulang harus diaudit untuk run baru: %+v", ev)
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
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Run ulang ditolak") {
		t.Fatalf("run ulang tanpa program harus ditolak:\n%s", rec.Body.String())
	}
	if n := len(srv.queue.List("")); n != 1 {
		t.Errorf("penolakan tak boleh menambah run, ada %d", n)
	}
	if ev := auditOf(t, al, "run.rerun"); len(ev) != 1 || ev[0].Allowed {
		t.Errorf("penolakan run ulang harus diaudit Allowed=false: %+v", ev)
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
			t.Errorf("viewer POST %s = %d, ingin 403", path, rec.Code)
		}
	}
	if b := authedReq(srv, "GET", "/dashboard/scans", nil, vc, vsess).Body.String(); strings.Contains(b, "/rerun") || strings.Contains(b, "/stop") || strings.Contains(b, "/delete") {
		t.Error("panel viewer tak boleh memuat tombol Stop/Run ulang/Hapus")
	}
	if b := authedReq(srv, "GET", "/dashboard/scans", nil, oc, osess).Body.String(); !strings.Contains(b, "/runs/"+id+"/rerun") || !strings.Contains(b, "/runs/"+id+"/delete") {
		t.Error("panel operator harus memuat tombol Run ulang & Hapus")
	}
	if rec := authedReq(srv, "POST", "/runs/"+id+"/rerun?view=dashboard", url.Values{}, oc, osess); rec.Code != http.StatusOK {
		t.Errorf("operator run ulang = %d, ingin 200", rec.Code)
	}
}

func TestScanSpecRedacted(t *testing.T) {
	sp := scanSpec{proxyChain: []string{"socks5://user:rahasia@10.0.0.1:1080"}, targets: []string{"demo.test"}}
	for _, f := range []string{"%v", "%+v", "%#v", "%s"} {
		if out := fmt.Sprintf(f, sp); strings.Contains(out, "rahasia") {
			t.Errorf("format %s membocorkan kredensial proxy: %s", f, out)
		}
	}
}

func TestRememberSpecBounded(t *testing.T) {
	srv, _ := newTestServer(t)
	for i := range rerunKeep + 5 {
		srv.rememberSpec(fmt.Sprintf("run%d", i), scanSpec{})
	}
	if _, ok := srv.specFor("run0"); ok {
		t.Error("spec tertua harus dibuang")
	}
	if _, ok := srv.specFor(fmt.Sprintf("run%d", rerunKeep+4)); !ok {
		t.Error("spec terbaru harus ada")
	}
	if n := len(srv.specs); n != rerunKeep {
		t.Errorf("spec diingat %d, ingin %d", n, rerunKeep)
	}
}
