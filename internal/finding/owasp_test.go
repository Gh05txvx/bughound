package finding

import (
	"testing"
	"time"
)

func TestClassifyOWASP_FromCWE(t *testing.T) {
	cases := map[string]OWASP{
		"CWE-89":  A03, // SQLi
		"CWE-79":  A03, // XSS
		"CWE-918": A10, // SSRF
		"CWE-200": A01, // exposure of sensitive info
		"CWE-22":  A01, // path traversal
		"CWE-611": A05, // XXE
		"CWE-614": A05, // sensitive cookie tanpa Secure
		"CWE-319": A02, // cleartext transmission
		"CWE-327": A02, // broken crypto
		"CWE-502": A08, // deserialization
		"CWE-798": A07, // hardcoded credentials
		"CWE-937": A06, // outdated components
	}
	for cwe, want := range cases {
		if got := ClassifyOWASP(&Finding{CWE: []string{cwe}}); got != want {
			t.Errorf("%s -> %s; want %s", cwe, got, want)
		}
	}
}

func TestClassifyOWASP_FromKeywords(t *testing.T) {
	cases := []struct {
		name string
		typ  string
		tags []string
		want OWASP
	}{
		{"zap csp header", "content-security-policy-csp-header-not-set", nil, A05},
		{"zap cors", "cross-domain-misconfiguration", nil, A05},
		{"zap suspicious comments", "information-disclosure-suspicious-comments", nil, A01},
		{"ffuf exposed path", "exposed-path", []string{"content-discovery"}, A05},
		{"nuclei ssrf tag", "some-template", []string{"ssrf", "cloud"}, A10},
		{"nuclei sqli tag", "rest-products-search", []string{"sqli", "dast"}, A03},
		{"retire deps", "vulnerable-dependency", []string{"dependency", "outdated", "sca"}, A06},
		{"prometheus metrics", "prometheus-metrics", []string{"exposure"}, A05},
		{"unclassifiable", "http", nil, OWASPNone},
	}
	for _, c := range cases {
		if got := ClassifyOWASP(&Finding{Type: c.typ, Tags: c.tags}); got != c.want {
			t.Errorf("%s: got %s; want %s", c.name, got, c.want)
		}
	}
}

func TestClassifyOWASP_CWEBeatsKeyword(t *testing.T) {
	// CWE lebih kuat dari kata kunci: SQLi (CWE-89) menang walau ada tag "exposure".
	f := &Finding{CWE: []string{"CWE-89"}, Tags: []string{"exposure"}, Type: "x"}
	if got := ClassifyOWASP(f); got != A03 {
		t.Errorf("CWE harus menang atas keyword: got %s want A03", got)
	}
}

func TestOWASPLabelValid(t *testing.T) {
	if A05.Label() != "A05:2021 Security Misconfiguration" {
		t.Errorf("label salah: %q", A05.Label())
	}
	if OWASPNone.Label() != "" {
		t.Error("OWASPNone.Label() harus kosong")
	}
	if !A01.Valid() || !OWASPNone.Valid() || OWASP("Z99").Valid() {
		t.Error("Valid() salah")
	}
}

func TestFinalizeSetsOWASP(t *testing.T) {
	// validFinding bertipe "ssrf" -> terklasifikasi A10 saat Finalize (dipanggil di helper).
	f := validFinding()
	if f.OWASP != A10 {
		t.Errorf("type ssrf harus -> A10; got %s", f.OWASP)
	}

	// Finalize tak menimpa OWASP yang sudah diisi (mis. oleh verifikator/adapter).
	f2 := &Finding{
		ID: "x", Program: "p", RunID: "r", Target: "https://a.io", Type: "sqli",
		Title: "t", Severity: SeverityHigh, Confidence: ConfidenceLow, Status: StatusNew,
		SourceEngine: "nuclei", Location: Location{URL: "https://a.io/x"}, OWASP: A05,
	}
	if err := f2.Finalize(time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	if f2.OWASP != A05 {
		t.Errorf("Finalize tak boleh menimpa OWASP preset; got %s", f2.OWASP)
	}
}
