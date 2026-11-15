package orchestrator

import (
	"context"
	"strings"
	"testing"

	"bughound/internal/finding"
	"bughound/internal/recon"
	"bughound/internal/store"
)

// authEngine (AuthAware) mencatat header yang diterima & memancarkan temuan yang
// evidence-nya memuat header itu — meniru engine yang meng-echo request mentah.
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

// authRecon (recon.Engine + AuthAware) mencatat header lalu memberi satu aset in-scope.
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

	// 1) engine & recon menerima header (plumbing lewat AuthAware).
	if len(eng.got) != 1 || eng.got[0] != "Cookie: session=SUPERSECRET" {
		t.Fatalf("engine tak menerima header auth: %v", eng.got)
	}
	if len(rec.got) != 1 || rec.got[0] != "Cookie: session=SUPERSECRET" {
		t.Fatalf("recon tak menerima header auth: %v", rec.got)
	}
	// 2) evidence tersimpan TANPA nilai cookie (redaksi di hulu sebelum Save).
	fs, _ := st.List(context.Background(), store.Query{Program: "demo"})
	if len(fs) == 0 {
		t.Fatal("tak ada temuan tersimpan")
	}
	req := fs[0].Evidence.Request
	if strings.Contains(req, "SUPERSECRET") {
		t.Errorf("secret cookie bocor ke evidence:\n%s", req)
	}
	if !strings.Contains(req, "Cookie: [REDACTED]") {
		t.Errorf("header Cookie harus terredaksi:\n%s", req)
	}
	// struktur lain utuh (request-line & Host tetap).
	if !strings.Contains(req, "GET /a HTTP/1.1") || !strings.Contains(req, "Host: demo.test") {
		t.Errorf("redaksi tak boleh merusak baris non-header:\n%s", req)
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
		t.Errorf("tanpa AuthHeaders, UseAuthHeaders tak boleh dipanggil; dapat %v", eng.got)
	}
}

func TestAuthHeadersStringRedacts(t *testing.T) {
	s := AuthHeaders{"Cookie: session=abc", "Authorization: Bearer xyz"}.String()
	for _, secret := range []string{"abc", "xyz", "session=abc", "Bearer"} {
		if strings.Contains(s, secret) {
			t.Errorf("String() membocorkan %q: %s", secret, s)
		}
	}
	for _, name := range []string{"Cookie", "Authorization"} {
		if !strings.Contains(s, name) {
			t.Errorf("String() harus pertahankan nama %q: %s", name, s)
		}
	}
}

func TestAuthHeadersNames(t *testing.T) {
	got := AuthHeaders{"Cookie: a", "Authorization: b", "  X-Api-Key : c", "garbage"}.Names()
	want := []string{"Cookie", "Authorization", "X-Api-Key"}
	if len(got) != len(want) {
		t.Fatalf("names=%v mau %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("name[%d]=%q mau %q", i, got[i], want[i])
		}
	}
}
