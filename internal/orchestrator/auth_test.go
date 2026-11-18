package orchestrator

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"bughound/internal/finding"
	"bughound/internal/recon"
	"bughound/internal/store"
)

// authEngine (AuthAware) records the headers it receives and emits a finding
// whose evidence contains them, like an engine that echoes the raw request.
type authEngine struct {
	got    []string
	cookie string
}

func (*authEngine) Name() string                { return "authfake" }
func (e *authEngine) UseAuthHeaders(h []string) { e.got = h }
func (e *authEngine) Scan(_ context.Context, _ string, program, runID string) ([]*finding.Finding, error) {
	return []*finding.Finding{{
		Program: program, RunID: runID, Target: "https://demo.test",
		Type: "x", Title: "x", Severity: finding.SeverityLow, Confidence: finding.ConfidenceLow,
		Status: finding.StatusNew, SourceEngine: "authfake",
		Location: finding.Location{URL: "https://demo.test/a"},
		Evidence: &finding.Evidence{Request: "GET /a HTTP/1.1\r\nHost: demo.test\r\nCookie: " + e.cookie + "\r\n\r\n"},
	}}, nil
}

// authRecon (recon.Engine + AuthAware) records the headers, then returns one in-scope asset.
type authRecon struct{ got []string }

func (*authRecon) Name() string                { return "authrecon" }
func (r *authRecon) UseAuthHeaders(h []string) { r.got = h }
func (*authRecon) Discover(_ context.Context, _ []string) ([]recon.Asset, error) {
	return []recon.Asset{{Value: "demo.test", Source: "katana"}}, nil
}

func TestAuthHeadersPlumbedAndEvidenceRedacted(t *testing.T) {
	g := newGuard(t, []string{"demo.test"}, nil)
	st := store.NewMem()
	eng := &authEngine{cookie: "session=SUPERSECRET"}
	rec := &authRecon{}
	o := New(g, eng, st, testLimiter(), nil)
	o.UseRecon(rec)

	_, err := o.RunScan(context.Background(), ScanRequest{
		Program: "demo", RunID: "r1", Seeds: []string{"demo.test"}, Targets: []string{"demo.test"},
		AuthHeaders: AuthHeaders{"Cookie: session=SUPERSECRET"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// 1) the engine and recon receive the headers (plumbing through AuthAware).
	if len(eng.got) != 1 || eng.got[0] != "Cookie: session=SUPERSECRET" {
		t.Fatalf("the engine did not receive the auth headers: %v", eng.got)
	}
	if len(rec.got) != 1 || rec.got[0] != "Cookie: session=SUPERSECRET" {
		t.Fatalf("recon did not receive the auth headers: %v", rec.got)
	}
	// 2) the evidence is stored WITHOUT the cookie value (redacted upstream, before Save).
	fs, _ := st.List(context.Background(), store.Query{Program: "demo"})
	if len(fs) == 0 {
		t.Fatal("no finding was stored")
	}
	req := fs[0].Evidence.Request
	if strings.Contains(req, "SUPERSECRET") {
		t.Errorf("the cookie secret leaked into the evidence:\n%s", req)
	}
	if !strings.Contains(req, "Cookie: [REDACTED]") {
		t.Errorf("the Cookie header must be redacted:\n%s", req)
	}
	// the rest of the structure is intact (request line and Host stay).
	if !strings.Contains(req, "GET /a HTTP/1.1") || !strings.Contains(req, "Host: demo.test") {
		t.Errorf("redaction must not damage non-header lines:\n%s", req)
	}
}

func TestAuthHeadersNotPlumbedWhenEmpty(t *testing.T) {
	g := newGuard(t, []string{"demo.test"}, nil)
	eng := &authEngine{cookie: "x"}
	o := New(g, eng, store.NewMem(), testLimiter(), nil)
	if _, err := o.RunScan(context.Background(), ScanRequest{
		Program: "demo", RunID: "r1", Targets: []string{"demo.test"},
	}); err != nil {
		t.Fatal(err)
	}
	if eng.got != nil {
		t.Errorf("without AuthHeaders, UseAuthHeaders must not be called; got %v", eng.got)
	}
}

func TestAuthHeadersStringRedacts(t *testing.T) {
	s := AuthHeaders{"Cookie: session=abc", "Authorization: Bearer xyz"}.String()
	for _, secret := range []string{"abc", "xyz", "session=abc", "Bearer"} {
		if strings.Contains(s, secret) {
			t.Errorf("String() leaks %q: %s", secret, s)
		}
	}
	for _, name := range []string{"Cookie", "Authorization"} {
		if !strings.Contains(s, name) {
			t.Errorf("String() must keep the name %q: %s", name, s)
		}
	}
}

// echoEngine and echoRecon (AuthAware) fail with an error that echoes the auth
// headers, like a tool that prints its argv/config to stderr.
type echoEngine struct{ got []string }

func (*echoEngine) Name() string                { return "echofail" }
func (e *echoEngine) UseAuthHeaders(h []string) { e.got = h }
func (e *echoEngine) Scan(context.Context, string, string, string) ([]*finding.Finding, error) {
	return nil, fmt.Errorf("exit 1 (bad -H %s)", strings.Join(e.got, " | "))
}

type echoRecon struct{ got []string }

func (*echoRecon) Name() string                { return "echorecon" }
func (r *echoRecon) UseAuthHeaders(h []string) { r.got = h }
func (r *echoRecon) Discover(context.Context, []string) ([]recon.Asset, error) {
	return nil, fmt.Errorf("katana: bad header %s", strings.Join(r.got, " | "))
}

// Engine and recon errors (which go into the append-only audit and the run
// summary) must not contain auth header values.
func TestAuthHeadersScrubbedFromErrors(t *testing.T) {
	hdrs := AuthHeaders{"Cookie: session=SUPERSECRET", "Authorization: Bearer TOKEN123"}
	g := newGuard(t, []string{"demo.test"}, nil)
	noLeak := func(where, s string) {
		t.Helper()
		if strings.Contains(s, "SUPERSECRET") || strings.Contains(s, "TOKEN123") {
			t.Errorf("%s leaks a header value: %s", where, s)
		}
		if !strings.Contains(s, "Cookie: [REDACTED]") {
			t.Errorf("%s must still contain the header name + [REDACTED]: %s", where, s)
		}
	}

	o := New(g, &echoEngine{}, store.NewMem(), testLimiter(), nil)
	res, err := o.RunScan(context.Background(), ScanRequest{Program: "demo", RunID: "r1", Targets: []string{"demo.test"}, AuthHeaders: hdrs})
	if err != nil || len(res.EngineErrors) != 1 {
		t.Fatalf("want 1 EngineError and no run error: err=%v errs=%v", err, res.EngineErrors)
	}
	noLeak("EngineError", res.EngineErrors[0].Err)

	o = New(g, &echoEngine{}, store.NewMem(), testLimiter(), nil)
	o.UseRecon(&echoRecon{})
	if _, err = o.RunScan(context.Background(), ScanRequest{Program: "demo", RunID: "r2", Seeds: []string{"demo.test"}, AuthHeaders: hdrs}); err == nil {
		t.Fatal("a failed recon must fail the run")
	}
	noLeak("recon error", err.Error())
}

func TestAuthHeadersScrubLongestFirst(t *testing.T) {
	if got := (AuthHeaders{"A: abc", "B: abcdef"}).Scrub("x abcdef y abc"); got != "x [REDACTED] y [REDACTED]" {
		t.Errorf("a value that contains another value must not be left partly visible: %q", got)
	}
	if got := (AuthHeaders(nil)).Scrub("intact"); got != "intact" {
		t.Errorf("without headers the text must be intact: %q", got)
	}
}

// reconWith returns fixed assets, like katana/gau finding a logout URL.
type reconWith struct{ assets []string }

func (*reconWith) Name() string { return "reconwith" }
func (r *reconWith) Discover(context.Context, []string) ([]recon.Asset, error) {
	out := make([]recon.Asset, 0, len(r.assets))
	for _, v := range r.assets {
		out = append(out, recon.Asset{Value: v, Source: "katana"})
	}
	return out, nil
}

// Logged-in scan: logout routes are NOT scanned, whether they come from recon
// or from the targets (e.g. endpoints expanded from an OpenAPI spec), because
// one GET kills the session. Without auth they are scanned as usual.
func TestAuthScanSkipsLogoutTargets(t *testing.T) {
	for _, tc := range []struct {
		auth       AuthHeaders
		wantLogout bool
	}{{nil, true}, {AuthHeaders{"Cookie: s=1"}, false}} {
		o := New(newGuard(t, []string{"demo.test"}, nil), &authEngine{}, store.NewMem(), testLimiter(), nil)
		o.UseRecon(&reconWith{assets: []string{"https://demo.test/logout", "https://demo.test/account"}})
		res, err := o.RunScan(context.Background(), ScanRequest{
			Program: "demo", RunID: "r", Seeds: []string{"demo.test"}, AuthHeaders: tc.auth,
			Targets: []string{"https://demo.test/user/sign-out", "https://demo.test/user/1"},
		})
		if err != nil {
			t.Fatal(err)
		}
		got := strings.Join(res.Scanned, " ")
		for _, lo := range []string{"/logout", "/user/sign-out"} {
			if strings.Contains(got, lo) != tc.wantLogout {
				t.Errorf("auth=%v: %s scanned=%v, want %v (scanned: %s)", tc.auth.Names(), lo, !tc.wantLogout, tc.wantLogout, got)
			}
		}
		for _, keep := range []string{"/account", "/user/1"} {
			if !strings.Contains(got, keep) {
				t.Errorf("auth=%v: %s (non-logout) must still be scanned (scanned: %s)", tc.auth.Names(), keep, got)
			}
		}
	}
}

func TestAuthHeadersNames(t *testing.T) {
	got := AuthHeaders{"Cookie: a", "Authorization: b", "  X-Api-Key : c", "garbage"}.Names()
	want := []string{"Cookie", "Authorization", "X-Api-Key"}
	if len(got) != len(want) {
		t.Fatalf("names=%v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("name[%d]=%q want %q", i, got[i], want[i])
		}
	}
}
