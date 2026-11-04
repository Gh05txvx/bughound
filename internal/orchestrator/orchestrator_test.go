package orchestrator

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"bughound/internal/engine/ffuf"
	"bughound/internal/engine/nuclei"
	"bughound/internal/finding"
	"bughound/internal/ratelimit"
	"bughound/internal/recon"
	"bughound/internal/scope"
	"bughound/internal/store"
)

func newGuard(t *testing.T, in, out []string) *scope.Guard {
	t.Helper()
	g, errs := scope.New(in, out)
	if len(errs) > 0 {
		t.Fatalf("scope.New errs tak terduga: %v", errs)
	}
	return g
}

// testLimiter: burst besar supaya test tak melambat (laju efektif dijepit ke maks).
func testLimiter() *ratelimit.Limiter {
	return ratelimit.New(ratelimit.Config{RequestsPerSecond: 1000, Burst: 1000})
}

// TestRunScanGate membuktikan gate M0 masih berlaku: satu temuan mengalir scan
// -> normalisasi -> store; target luar scope ditolak; secret tak bocor.
func TestRunScanGate(t *testing.T) {
	g := newGuard(t, []string{"demo.test", "*.demo.test"}, nil)
	st := store.NewMem()
	var audit []AuditEvent
	o := New(g, nuclei.Mock{}, st, testLimiter(), func(e AuditEvent) { audit = append(audit, e) })

	res, err := o.RunScan(context.Background(), ScanRequest{
		Program: "demo", RunID: "run1", Targets: []string{"demo.test", "evil.test"},
	})
	if err != nil {
		t.Fatalf("RunScan error: %v", err)
	}
	if res.FindingsSaved != 2 || res.Duplicates != 0 {
		t.Errorf("ingin 2 tersimpan / 0 duplikat; dapat saved=%d dup=%d", res.FindingsSaved, res.Duplicates)
	}
	if len(res.Scanned) != 1 || res.Scanned[0] != "demo.test" {
		t.Errorf("hanya demo.test yang discan; dapat %v", res.Scanned)
	}
	var deniedEvil *AuditEvent
	for i := range res.Denied {
		if res.Denied[i].Target == "evil.test" {
			deniedEvil = &res.Denied[i]
		}
	}
	if deniedEvil == nil || deniedEvil.Layer != LayerInput || deniedEvil.Reason != scope.ReasonNotInScope {
		t.Errorf("evil.test harus ditolak di lapis input (not-in-scope); dapat %+v", res.Denied)
	}
	fs, _ := st.List(context.Background(), store.Query{Program: "demo"})
	if len(fs) != 2 || fs[0].Severity != finding.SeverityCritical {
		t.Fatalf("store tidak sesuai: %d temuan", len(fs))
	}
	for _, f := range fs {
		if f.Evidence != nil && strings.Contains(f.Evidence.Request, "SECRET-abc123") {
			t.Error("secret bocor ke store")
		}
	}
	if len(audit) == 0 {
		t.Error("audit trail kosong")
	}
}

func TestRunScanDedupSecondRun(t *testing.T) {
	g := newGuard(t, []string{"demo.test"}, nil)
	st := store.NewMem()
	o := New(g, nuclei.Mock{}, st, testLimiter(), nil)
	ctx := context.Background()

	if _, err := o.RunScan(ctx, ScanRequest{Program: "demo", RunID: "run1", Targets: []string{"demo.test"}}); err != nil {
		t.Fatal(err)
	}
	res2, err := o.RunScan(ctx, ScanRequest{Program: "demo", RunID: "run2", Targets: []string{"demo.test"}})
	if err != nil {
		t.Fatal(err)
	}
	if res2.FindingsSaved != 0 || res2.Duplicates != 2 {
		t.Errorf("run kedua harus semua duplikat; dapat saved=%d dup=%d", res2.FindingsSaved, res2.Duplicates)
	}
	fs, _ := st.List(ctx, store.Query{Program: "demo"})
	if len(fs) != 2 {
		t.Errorf("harus tetap 2 temuan utama; dapat %d", len(fs))
	}
}

type fakeEngine struct{ out []*finding.Finding }

func (fakeEngine) Name() string { return "fake" }

func (f fakeEngine) Scan(_ context.Context, _ string, program, runID string) ([]*finding.Finding, error) {
	var out []*finding.Finding
	for _, x := range f.out {
		c := *x
		c.Program, c.RunID = program, runID
		out = append(out, &c)
	}
	return out, nil
}

// errEngine selalu gagal — untuk membuktikan kegagalan satu engine tak
// membatalkan run.
type errEngine struct{}

func (errEngine) Name() string { return "boom" }
func (errEngine) Scan(_ context.Context, _, _, _ string) ([]*finding.Finding, error) {
	return nil, errors.New("engine meledak")
}

// TestRunScanEngineErrorNonFatal: engine yang gagal pada satu target TIDAK boleh
// membatalkan run — engine lain tetap menyimpan temuan, RunScan sukses, dan
// kegagalan tercatat di EngineErrors.
func TestRunScanEngineErrorNonFatal(t *testing.T) {
	g := newGuard(t, []string{"demo.test"}, nil)
	st := store.NewMem()
	good := fakeEngine{out: []*finding.Finding{{
		Target: "demo.test", Type: "x", Title: "t",
		Severity: finding.SeverityLow, Confidence: finding.ConfidenceLow,
		Status: finding.StatusNew, SourceEngine: "fake",
		Location: finding.Location{URL: "https://demo.test/a"},
	}}}
	o := New(g, errEngine{}, st, testLimiter(), nil) // engine pertama gagal
	o.AddEngine(good)                                // engine kedua sukses

	res, err := o.RunScan(context.Background(), ScanRequest{Program: "demo", RunID: "r", Targets: []string{"demo.test"}})
	if err != nil {
		t.Fatalf("kegagalan engine tak boleh membuat RunScan error: %v", err)
	}
	if res.FindingsSaved != 1 {
		t.Errorf("engine kedua harus tetap menyimpan 1 temuan; dapat saved=%d", res.FindingsSaved)
	}
	if len(res.EngineErrors) != 1 || res.EngineErrors[0].Engine != "boom" {
		t.Errorf("kegagalan engine harus tercatat di EngineErrors; dapat %+v", res.EngineErrors)
	}
}

// TestRunScanEgressBlocks membuktikan penegakan lapis kedua: temuan pada lokasi
// di luar scope dihadang walau target awal in-scope.
func TestRunScanEgressBlocks(t *testing.T) {
	g := newGuard(t, []string{"demo.test"}, nil)
	st := store.NewMem()
	var audit []AuditEvent
	eng := fakeEngine{out: []*finding.Finding{{
		Target: "demo.test", Type: "redirect-ssrf", Title: "leak via redirect",
		Severity: finding.SeverityHigh, Confidence: finding.ConfidenceMedium,
		Status: finding.StatusNew, SourceEngine: "fake",
		Location: finding.Location{URL: "https://external.evil/x"},
	}}}
	o := New(g, eng, st, testLimiter(), func(e AuditEvent) { audit = append(audit, e) })

	res, err := o.RunScan(context.Background(), ScanRequest{Program: "demo", RunID: "r", Targets: []string{"demo.test"}})
	if err != nil {
		t.Fatalf("RunScan error: %v", err)
	}
	if res.FindingsSaved != 0 {
		t.Errorf("temuan di luar scope tak boleh tersimpan; saved=%d", res.FindingsSaved)
	}
	if fs, _ := st.List(context.Background(), store.Query{Program: "demo"}); len(fs) != 0 {
		t.Errorf("store harus kosong; dapat %d", len(fs))
	}
	var egressDeny bool
	for _, e := range audit {
		if e.Layer == LayerEgress && !e.Allowed {
			egressDeny = true
		}
	}
	if !egressDeny {
		t.Error("harus ada audit egress-deny untuk temuan di luar scope")
	}
}

// TestRunScanWithRecon membuktikan alur recon → scope guard → DAST: aset recon
// yang in-scope discan; yang out-of-scope/di luar scope ditolak.
func TestRunScanWithRecon(t *testing.T) {
	g := newGuard(t, []string{"demo.test", "*.demo.test"}, []string{"admin.demo.test"})
	st := store.NewMem()
	o := New(g, nuclei.Mock{}, st, testLimiter(), nil)
	o.UseRecon(recon.MockPipeline{})

	res, err := o.RunScan(context.Background(), ScanRequest{
		Program: "demo", RunID: "run1", Seeds: []string{"demo.test"},
	})
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}
	if res.Discovered == 0 {
		t.Error("recon harus menemukan aset")
	}
	if len(res.Scanned) == 0 {
		t.Error("harus ada target in-scope yang discan")
	}
	if res.FindingsSaved != 2 {
		t.Errorf("mock DAST => 2 temuan utama; dapat %d", res.FindingsSaved)
	}

	denied := map[string]scope.Reason{}
	for _, e := range res.Denied {
		denied[e.Target] = e.Reason
	}
	if denied["admin.demo.test"] != scope.ReasonOutOfScope {
		t.Errorf("admin.demo.test harus ditolak out-of-scope; dapat %q", denied["admin.demo.test"])
	}
	if _, ok := denied["exfil.evil.test"]; !ok {
		t.Error("exfil.evil.test (di luar scope) harus ditolak")
	}

	all, _ := st.List(context.Background(), store.Query{Program: "demo", IncludeDuplicates: true})
	for _, f := range all {
		if strings.Contains(f.Target, "evil.test") {
			t.Error("temuan di luar scope tak boleh tersimpan")
		}
	}
}

// TestRunScanMultiEngine membuktikan >1 engine menulis ke skema yang sama.
func TestRunScanMultiEngine(t *testing.T) {
	g := newGuard(t, []string{"demo.test"}, nil)
	st := store.NewMem()
	o := New(g, nuclei.Mock{}, st, testLimiter(), nil)
	o.AddEngine(ffuf.Mock{})

	res, err := o.RunScan(context.Background(), ScanRequest{Program: "demo", RunID: "r", Targets: []string{"demo.test"}})
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}
	// 2 nuclei + 4 ffuf, semua dedup_key berbeda.
	if res.FindingsSaved != 6 {
		t.Errorf("ingin 6 temuan (2 nuclei + 4 ffuf), dapat %d", res.FindingsSaved)
	}
	all, _ := st.List(context.Background(), store.Query{Program: "demo"})
	var hasNuclei, hasFfuf bool
	for _, f := range all {
		switch f.SourceEngine {
		case "nuclei":
			hasNuclei = true
		case "ffuf":
			hasFfuf = true
		}
	}
	if !hasNuclei || !hasFfuf {
		t.Error("nuclei dan ffuf harus sama-sama menyumbang ke skema yang sama")
	}
}

// probeEngine adalah engine eksternal palsu yang MEMBUAT request HTTP nyata
// lewat proxy egress yang diberikan — untuk membuktikan proxy menegakkan scope
// pada koneksi engine sungguhan (tanpa butuh nuclei asli).
type probeEngine struct {
	proxyAddr string
	urls      []string
}

func (p *probeEngine) Name() string         { return "probe" }
func (p *probeEngine) UseProxy(addr string) { p.proxyAddr = addr }

func (p *probeEngine) Scan(_ context.Context, _, program, runID string) ([]*finding.Finding, error) {
	pu, _ := url.Parse("http://" + p.proxyAddr)
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
	var out []*finding.Finding
	for _, u := range p.urls {
		resp, err := client.Get(u)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			out = append(out, &finding.Finding{
				Program: program, RunID: runID, Target: u, Type: "probe-hit",
				Title: "reachable " + u, Severity: finding.SeverityInfo,
				Confidence: finding.ConfidenceHigh, Status: finding.StatusNew,
				SourceEngine: "probe", Location: finding.Location{URL: u},
			})
		}
	}
	return out, nil
}

// TestRunScanEgressProxyEnforcesScope membuktikan mekanisme pilihan pengguna:
// orchestrator menyalakan proxy egress untuk engine ProxyAware, dan koneksi
// engine ke host di luar scope DIBLOK sebelum terjadi.
func TestRunScanEgressProxyEnforcesScope(t *testing.T) {
	var hits int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Write([]byte("ok"))
	}))
	defer backend.Close()
	bu, _ := url.Parse(backend.URL)

	g := newGuard(t, []string{bu.Hostname()}, nil) // hanya host backend in-scope
	st := store.NewMem()
	eng := &probeEngine{urls: []string{backend.URL, "http://evil.test/x"}}
	o := New(g, eng, st, testLimiter(), nil)

	res, err := o.RunScan(context.Background(), ScanRequest{Program: "demo", RunID: "r", Targets: []string{bu.Hostname()}})
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}

	if res.FindingsSaved != 1 {
		t.Errorf("hanya probe in-scope yang berhasil => 1 temuan; dapat %d", res.FindingsSaved)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Errorf("backend in-scope harus kena tepat 1x; dapat %d", hits)
	}
	var blockedEvil bool
	for _, d := range res.Denied {
		if d.Layer == LayerEgress && strings.Contains(d.Target, "evil.test") {
			blockedEvil = true
		}
	}
	if !blockedEvil {
		t.Error("proxy egress harus menolak koneksi ke evil.test (lapis egress)")
	}
}

// ProxyChain.String meredaksi kredensial proxy (Prinsip #5): host tetap
// tampil, user:pass tidak pernah.
func TestProxyChainStringRedactsCreds(t *testing.T) {
	pc := ProxyChain{"http://user:s3cr3t@proxy.local:8080", "socks5://bob:p4ss@127.0.0.1:9050"}
	s := pc.String()
	for _, leak := range []string{"s3cr3t", "p4ss", "user", "bob"} {
		if strings.Contains(s, leak) {
			t.Errorf("ProxyChain.String membocorkan kredensial %q: %s", leak, s)
		}
	}
	for _, host := range []string{"proxy.local:8080", "127.0.0.1:9050"} {
		if !strings.Contains(s, host) {
			t.Errorf("host harus tetap tampil (%s): %s", host, s)
		}
	}
}
