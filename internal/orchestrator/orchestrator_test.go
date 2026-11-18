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
		t.Fatalf("unexpected scope.New errs: %v", errs)
	}
	return g
}

// testLimiter: a large burst so tests do not slow down (the effective rate is clamped to the max).
func testLimiter() *ratelimit.Limiter {
	return ratelimit.New(ratelimit.Config{RequestsPerSecond: 1000, Burst: 1000})
}

// TestRunScanGate shows the M0 gate still holds: one finding flows scan ->
// normalization -> store; an out-of-scope target is denied; no secret leaks.
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
		t.Errorf("want 2 saved / 0 duplicates; got saved=%d dup=%d", res.FindingsSaved, res.Duplicates)
	}
	if len(res.Scanned) != 1 || res.Scanned[0] != "demo.test" {
		t.Errorf("only demo.test should be scanned; got %v", res.Scanned)
	}
	var deniedEvil *AuditEvent
	for i := range res.Denied {
		if res.Denied[i].Target == "evil.test" {
			deniedEvil = &res.Denied[i]
		}
	}
	if deniedEvil == nil || deniedEvil.Layer != LayerInput || deniedEvil.Reason != scope.ReasonNotInScope {
		t.Errorf("evil.test must be denied at the input layer (not-in-scope); got %+v", res.Denied)
	}
	fs, _ := st.List(context.Background(), store.Query{Program: "demo"})
	if len(fs) != 2 || fs[0].Severity != finding.SeverityCritical {
		t.Fatalf("unexpected store content: %d findings", len(fs))
	}
	for _, f := range fs {
		if f.Evidence != nil && strings.Contains(f.Evidence.Request, "SECRET-abc123") {
			t.Error("a secret leaked into the store")
		}
	}
	if len(audit) == 0 {
		t.Error("the audit trail is empty")
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
		t.Errorf("the second run must be all duplicates; got saved=%d dup=%d", res2.FindingsSaved, res2.Duplicates)
	}
	fs, _ := st.List(ctx, store.Query{Program: "demo"})
	if len(fs) != 2 {
		t.Errorf("there must still be 2 main findings; got %d", len(fs))
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

// errEngine always fails. It shows that one engine failing does not abort the
// run.
type errEngine struct{}

func (errEngine) Name() string { return "boom" }
func (errEngine) Scan(_ context.Context, _, _, _ string) ([]*finding.Finding, error) {
	return nil, errors.New("engine blew up")
}

// TestRunScanEngineErrorNonFatal: an engine that fails on one target must NOT
// abort the run. The other engine still saves its finding, RunScan succeeds and
// the failure is recorded in EngineErrors.
func TestRunScanEngineErrorNonFatal(t *testing.T) {
	g := newGuard(t, []string{"demo.test"}, nil)
	st := store.NewMem()
	good := fakeEngine{out: []*finding.Finding{{
		Target: "demo.test", Type: "x", Title: "t",
		Severity: finding.SeverityLow, Confidence: finding.ConfidenceLow,
		Status: finding.StatusNew, SourceEngine: "fake",
		Location: finding.Location{URL: "https://demo.test/a"},
	}}}
	o := New(g, errEngine{}, st, testLimiter(), nil) // the first engine fails
	o.AddEngine(good)                                // the second engine succeeds

	res, err := o.RunScan(context.Background(), ScanRequest{Program: "demo", RunID: "r", Targets: []string{"demo.test"}})
	if err != nil {
		t.Fatalf("an engine failure must not make RunScan error: %v", err)
	}
	if res.FindingsSaved != 1 {
		t.Errorf("the second engine must still save 1 finding; got saved=%d", res.FindingsSaved)
	}
	if len(res.EngineErrors) != 1 || res.EngineErrors[0].Engine != "boom" {
		t.Errorf("the engine failure must be recorded in EngineErrors; got %+v", res.EngineErrors)
	}
}

// TestRunScanEgressBlocks shows the second enforcement layer: a finding at an
// out-of-scope location is blocked even though the initial target is in scope.
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
		t.Errorf("an out-of-scope finding must not be saved; saved=%d", res.FindingsSaved)
	}
	if fs, _ := st.List(context.Background(), store.Query{Program: "demo"}); len(fs) != 0 {
		t.Errorf("the store must be empty; got %d", len(fs))
	}
	// The finding is judged after the engine finishes, so it must not be recorded
	// as a blocked connection: the egress layer is only for denials before a
	// connection.
	var findingDeny bool
	for _, e := range audit {
		if !e.Allowed && e.Layer == LayerFinding {
			findingDeny = true
		}
		if !e.Allowed && e.Layer == LayerEgress {
			t.Errorf("the finding was recorded as a connection denial: %+v", e)
		}
	}
	if !findingDeny {
		t.Error("there must be an audit entry for the denied out-of-scope finding")
	}
}

// TestRunScanWithRecon shows the recon → scope guard → DAST flow: in-scope
// recon assets are scanned; out-of-scope ones are denied.
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
		t.Error("recon must find assets")
	}
	if len(res.Scanned) == 0 {
		t.Error("an in-scope target must be scanned")
	}
	if res.FindingsSaved != 2 {
		t.Errorf("mock DAST => 2 main findings; got %d", res.FindingsSaved)
	}

	denied := map[string]scope.Reason{}
	for _, e := range res.Denied {
		denied[e.Target] = e.Reason
	}
	if denied["admin.demo.test"] != scope.ReasonOutOfScope {
		t.Errorf("admin.demo.test must be denied as out-of-scope; got %q", denied["admin.demo.test"])
	}
	if _, ok := denied["exfil.evil.test"]; !ok {
		t.Error("exfil.evil.test (out of scope) must be denied")
	}

	all, _ := st.List(context.Background(), store.Query{Program: "demo", IncludeDuplicates: true})
	for _, f := range all {
		if strings.Contains(f.Target, "evil.test") {
			t.Error("an out-of-scope finding must not be saved")
		}
	}
}

// TestRunScanMultiEngine shows that more than one engine writes to the same schema.
func TestRunScanMultiEngine(t *testing.T) {
	g := newGuard(t, []string{"demo.test"}, nil)
	st := store.NewMem()
	o := New(g, nuclei.Mock{}, st, testLimiter(), nil)
	o.AddEngine(ffuf.Mock{})

	res, err := o.RunScan(context.Background(), ScanRequest{Program: "demo", RunID: "r", Targets: []string{"demo.test"}})
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}
	// 2 nuclei + 4 ffuf, all with different dedup_keys.
	if res.FindingsSaved != 6 {
		t.Errorf("want 6 findings (2 nuclei + 4 ffuf), got %d", res.FindingsSaved)
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
		t.Error("nuclei and ffuf must both contribute to the same schema")
	}
}

// probeEngine is a fake external engine that MAKES real HTTP requests through
// the egress proxy it is given. It shows the proxy enforces scope on a real
// engine connection (without needing real nuclei).
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

// TestRunScanEgressProxyEnforcesScope shows the mechanism the user chose: the
// orchestrator starts the egress proxy for ProxyAware engines, and an engine
// connection to an out-of-scope host is BLOCKED before it happens.
func TestRunScanEgressProxyEnforcesScope(t *testing.T) {
	var hits int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Write([]byte("ok"))
	}))
	defer backend.Close()
	bu, _ := url.Parse(backend.URL)

	g := newGuard(t, []string{bu.Hostname()}, nil) // only the backend host is in scope
	st := store.NewMem()
	eng := &probeEngine{urls: []string{backend.URL, "http://evil.test/x"}}
	o := New(g, eng, st, testLimiter(), nil)

	res, err := o.RunScan(context.Background(), ScanRequest{Program: "demo", RunID: "r", Targets: []string{bu.Hostname()}})
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}

	if res.FindingsSaved != 1 {
		t.Errorf("only the in-scope probe succeeds => 1 finding; got %d", res.FindingsSaved)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Errorf("the in-scope backend must be hit exactly once; got %d", hits)
	}
	var blockedEvil bool
	for _, d := range res.Denied {
		if d.Layer == LayerEgress && strings.Contains(d.Target, "evil.test") {
			blockedEvil = true
		}
	}
	if !blockedEvil {
		t.Error("the egress proxy must deny the connection to evil.test (egress layer)")
	}
}

// ProxyChain.String redacts proxy credentials (Principle #5): the host is still
// shown, user:pass never is.
func TestProxyChainStringRedactsCreds(t *testing.T) {
	pc := ProxyChain{"http://user:s3cr3t@proxy.local:8080", "socks5://bob:p4ss@127.0.0.1:9050"}
	s := pc.String()
	for _, leak := range []string{"s3cr3t", "p4ss", "user", "bob"} {
		if strings.Contains(s, leak) {
			t.Errorf("ProxyChain.String leaks the credential %q: %s", leak, s)
		}
	}
	for _, host := range []string{"proxy.local:8080", "127.0.0.1:9050"} {
		if !strings.Contains(s, host) {
			t.Errorf("the host must still be shown (%s): %s", host, s)
		}
	}
}
