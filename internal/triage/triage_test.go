package triage

import (
	"math"
	"testing"
	"time"

	"bughound/internal/finding"
)

func approx(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func eqFloats(a, b []float64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !approx(a[i], b[i]) {
			return false
		}
	}
	return true
}

// mk builds a minimal test Finding (every required field set, to stay realistic).
func mk(id string, opts ...func(*finding.Finding)) *finding.Finding {
	f := &finding.Finding{
		SchemaVersion: finding.CurrentSchemaVersion,
		ID:            id,
		DedupKey:      id, // default: each finding is its own cluster
		Program:       "demo",
		RunID:         "run1",
		Target:        "https://demo.test",
		Type:          "generic",
		Title:         "generic",
		Severity:      finding.SeverityMedium,
		Confidence:    finding.ConfidenceMedium,
		SourceEngine:  "nuclei",
		Status:        finding.StatusNew,
		Location:      finding.Location{URL: "https://demo.test/x"},
		CreatedAt:     finding.NewTime(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)),
	}
	for _, o := range opts {
		o(f)
	}
	return f
}

func sev(s finding.Severity) func(*finding.Finding) {
	return func(f *finding.Finding) { f.Severity = s }
}
func conf(c finding.Confidence) func(*finding.Finding) {
	return func(f *finding.Finding) { f.Confidence = c }
}
func eng(e string) func(*finding.Finding) { return func(f *finding.Finding) { f.SourceEngine = e } }
func typ(t string) func(*finding.Finding) {
	return func(f *finding.Finding) { f.Type = t; f.Title = t }
}
func stat(s finding.Status) func(*finding.Finding) { return func(f *finding.Finding) { f.Status = s } }
func owasp(o finding.OWASP) func(*finding.Finding) { return func(f *finding.Finding) { f.OWASP = o } }
func dedup(k string) func(*finding.Finding)        { return func(f *finding.Finding) { f.DedupKey = k } }

func TestNormalize(t *testing.T) {
	// Mirror analyst/tests/test_saw.py::test_normalize_benefit_and_cost.
	if got := normalize([]float64{5, 10, 0}, "benefit"); !eqFloats(got, []float64{0.5, 1.0, 0.0}) {
		t.Errorf("benefit = %v", got)
	}
	if got := normalize([]float64{2, 4, 0}, "cost"); !eqFloats(got, []float64{1.0, 0.5, 1.0}) {
		t.Errorf("cost = %v", got)
	}
	if got := normalize(nil, "benefit"); len(got) != 0 {
		t.Errorf("empty = %v", got)
	}
}

func TestSignal(t *testing.T) {
	tests := []struct {
		name, text, extra string
		want              float64
	}{
		{"noise header", "x-xss-protection header missing", "", 0.1},
		{"noise csp", "content-security-policy misconfigured", "", 0.1},
		{"high reflected xss", "reflected xss", "", 1.0},
		{"high sql injection phrase", "sql injection in search", "", 1.0},
		{"neutral default", "big-redirect detected", "", 0.5},
		// substring safety: a short pattern must not match as a substring.
		{"rce not in resource", "exposed resource endpoint", "", 0.5},
		{"xss only via x-xss-protection stays noise", "x-xss-protection", "", 0.1},
		// the path (extra) only PROMOTES to high; it never demotes.
		{"path promote to git", "exposed-path", "/.git/config", 1.0},
		{"path neutral asset", "exposed-path", "/assets/app.js", 0.5},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := signal(tc.text, tc.extra); !approx(got, tc.want) {
				t.Errorf("signal(%q,%q) = %v, want %v", tc.text, tc.extra, got, tc.want)
			}
		})
	}
}

func TestIsBoringPath(t *testing.T) {
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"/robots.txt", true},
		{"/.well-known/security.txt", true},
		{"/favicon.ico", true},
		{"/admin", false},
		{"/.git/config", false},
		{"", false},
	} {
		if got := isBoringPath(tc.path); got != tc.want {
			t.Errorf("isBoringPath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestFpLikelihood(t *testing.T) {
	for _, tc := range []struct {
		name string
		f    *finding.Finding
		want float64
	}{
		{"confirmed", mk("a", stat(finding.StatusConfirmed)), 0.0},
		{"dast high", mk("b", eng("nuclei-dast"), conf(finding.ConfidenceHigh)), 0.1},
		{"ffuf spa", mk("c", eng("ffuf"), func(f *finding.Finding) {
			f.Evidence = &finding.Evidence{ResponseExcerpt: `<!doctype html><div id="root"></div>`}
		}), 0.7},
		{"retire low", mk("d", eng("retire"), conf(finding.ConfidenceLow)), 0.5},
		{"default", mk("e"), 0.3},
	} {
		if got := fpLikelihood(tc.f); !approx(got, tc.want) {
			t.Errorf("%s: fpLikelihood = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestHostPath(t *testing.T) {
	for _, tc := range []struct {
		url, host, path string
	}{
		{"https://ex.test:8443/a/b?q=1", "ex.test:8443", "/a/b"},
		{"http://ex.test/.git/config#x", "ex.test", "/.git/config"},
		{"ex.test/Admin", "ex.test", "/admin"},
		{"https://ex.test", "ex.test", ""},
	} {
		if got := host(tc.url); got != tc.host {
			t.Errorf("host(%q) = %q, want %q", tc.url, got, tc.host)
		}
		if got := pathOf(tc.url); got != tc.path {
			t.Errorf("pathOf(%q) = %q, want %q", tc.url, got, tc.path)
		}
	}
}

func TestEffortOf(t *testing.T) {
	// first match wins: "blind-sqli" → sqli(2) because sqli comes before blind.
	for _, tc := range []struct {
		typ  string
		want int
	}{
		{"reflected-xss", 1}, {"blind-sqli", 2}, {"ssrf", 3}, {"unknown", 2},
	} {
		if got := effortOf(tc.typ); got != tc.want {
			t.Errorf("effortOf(%q) = %d, want %d", tc.typ, got, tc.want)
		}
	}
}

// TestRankGolden pins the full SAW pipeline: two findings that are identical
// except for severity (high vs low) → every other criterion normalizes to the
// same value (1.0), and only severity+bounty (the severity proxy) differ. The
// scores can be worked out by hand: high = Σ all weights = 1.00 ; low = 1.00 −
// 0.12·0.5 − 0.16·0.5 = 0.86.
func TestRankGolden(t *testing.T) {
	base := func(id string, s finding.Severity) *finding.Finding {
		return mk(id, dedup(id), typ("sqli"), eng("nuclei-dast"),
			conf(finding.ConfidenceHigh), owasp(finding.A03), sev(s))
	}
	hi := base("hi", finding.SeverityHigh)
	lo := base("lo", finding.SeverityLow)

	got := Rank([]*finding.Finding{lo, hi}) // input order is low first on purpose
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0].Finding.ID != "hi" || got[0].Rank != 1 || !approx(got[0].Score, 1.0) {
		t.Errorf("rank1 = %+v (score %v), want hi/1/1.00", got[0].Finding.ID, got[0].Score)
	}
	if got[1].Finding.ID != "lo" || got[1].Rank != 2 || !approx(got[1].Score, 0.86) {
		t.Errorf("rank2 = %+v (score %v), want lo/2/0.86", got[1].Finding.ID, got[1].Score)
	}
}

// TestRankSignalBeatsSeverity: a MEDIUM severity header-hygiene finding must
// lose to a MEDIUM severity SQLi. That is what the "signal" lever against
// header noise is for.
func TestRankSignalBeatsSeverity(t *testing.T) {
	sqli := mk("sqli", dedup("sqli"), typ("sql injection"), eng("nuclei-dast"),
		conf(finding.ConfidenceHigh), sev(finding.SeverityMedium), owasp(finding.A03))
	header := mk("hdr", dedup("hdr"), typ("x-xss-protection header missing"),
		eng("zap-passive"), conf(finding.ConfidenceLow), sev(finding.SeverityMedium))

	got := Rank([]*finding.Finding{header, sqli})
	if got[0].Finding.ID != "sqli" {
		t.Fatalf("rank1 = %q, want sqli (signal must beat header noise)", got[0].Finding.ID)
	}
	// The top drivers for the SQLi must include exploitability/signal, not severity.
	top := got[0].TopFactors(2)
	if len(top) != 2 {
		t.Fatalf("TopFactors len = %d", len(top))
	}
	seen := map[string]bool{top[0].Name: true, top[1].Name: true}
	if !seen["exploitability"] && !seen["signal"] {
		t.Errorf("top factors = %v, should be dominated by exploitability/signal", top)
	}
}

// TestPrefilter: drop duplicate/FP/ignored statuses and info; collapse each
// cluster to its highest severity; one representative per dedup_key.
func TestPrefilter(t *testing.T) {
	in := []*finding.Finding{
		mk("1", dedup("k1"), sev(finding.SeverityLow)),
		mk("2", dedup("k1"), sev(finding.SeverityHigh)),         // representative of cluster k1 (highest sev)
		mk("3", dedup("k2"), sev(finding.SeverityInfo)),         // dropped (info)
		mk("4", dedup("k3"), stat(finding.StatusDuplicate)),     // dropped (duplicate)
		mk("5", dedup("k4"), stat(finding.StatusFalsePositive)), // dropped (FP)
		mk("6", dedup("k5"), sev(finding.SeverityMedium)),
	}
	got := prefilter(in)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2 (k1 representative + k5)", len(got))
	}
	byID := map[string]bool{}
	for _, f := range got {
		byID[f.ID] = true
	}
	if !byID["2"] {
		t.Errorf("cluster k1 must be represented by finding '2' (severity high), got %v", byID)
	}
	if !byID["6"] {
		t.Errorf("k5 ('6') is missing, got %v", byID)
	}
}

func TestRankEmptyAfterPrefilter(t *testing.T) {
	in := []*finding.Finding{
		mk("1", sev(finding.SeverityInfo)),
		mk("2", stat(finding.StatusIgnored)),
	}
	if got := Rank(in); got != nil {
		t.Errorf("Rank = %v, want nil (everything filtered out)", got)
	}
}
