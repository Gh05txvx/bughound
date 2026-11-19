package report

import (
	"strings"
	"testing"

	"bughound/internal/finding"
)

func TestCaveats(t *testing.T) {
	items := []*finding.Finding{
		{Type: "off-site-redirect", Title: "Off-site Redirect", Severity: finding.SeverityMedium, Target: "http://t:8080", Location: finding.Location{URL: "http://t:8080/go?url=x", Parameter: "url"}, CWE: []string{"CWE-601"}},
		{Type: "path-traversal", Title: "Path Traversal", Severity: finding.SeverityHigh, Target: "http://t:8080", Location: finding.Location{URL: "http://t:8080/go?url=go", Parameter: "url"}, CWE: []string{"CWE-22"}},
		{Type: "cross-site-scripting-reflected", Title: "Cross Site Scripting (Reflected)", Severity: finding.SeverityHigh, Target: "http://t:8080", Location: finding.Location{URL: "http://t:8080/search?q=x", Parameter: "q"}, CWE: []string{"CWE-79"}},
		{Type: "cookies-without-secure", Title: "Cookies without Secure attribute", Severity: finding.SeverityInfo, Target: "http://t:8080", Location: finding.Location{URL: "http://t:8080/"}, CWE: []string{"CWE-614"}},
		{Type: "format-string-error", Title: "Format String Error", Severity: finding.SeverityMedium, Target: "http://t:8080", Location: finding.Location{URL: "http://t:8080/contact"}},
		{Type: "csp-style-src-unsafe-inline", Title: "CSP", Severity: finding.SeverityMedium, Target: "http://t:8080", Location: finding.Location{URL: "http://t:8080/admin/", Parameter: "Content-Security-Policy"}},
		{Type: "session-management-response-identified", Title: "Session Management", Severity: finding.SeverityInfo, Target: "http://t:8080", Location: finding.Location{URL: "http://t:8080/login?next=/admin/", Parameter: "session"}},
	}
	cavs := Caveats(items)

	want := []struct{ kind, substr string }{
		{"fp", "/go"},             // traversal on the redirect sink
		{"fp", "plain HTTP"},      // cookie-Secure on a plain-HTTP target
		{"fp", "Format String"},   // noisy ZAP active check
		{"coverage", "auth wall"}, // login?next=/admin/
		{"coverage", "seed deep"}, // standing reminder (gated content present)
	}
	for _, w := range want {
		if !hasCaveat(cavs, w.kind, w.substr) {
			t.Errorf("missing %s caveat containing %q; got %+v", w.kind, w.substr, cavs)
		}
	}

	// The reflected XSS on /search is a real finding, not a redirect-sink FP.
	for _, c := range cavs {
		if c.Kind == "fp" && strings.Contains(c.Title, "/search") {
			t.Errorf("the /search XSS must NOT be flagged as a redirect-sink FP: %+v", c)
		}
	}

	// A lone real finding on an HTTPS target yields no caveats (no noise).
	clean := []*finding.Finding{
		{Type: "cross-site-scripting-reflected", Title: "XSS", Severity: finding.SeverityHigh, Target: "https://t", Location: finding.Location{URL: "https://t/search?q=x", Parameter: "q"}, CWE: []string{"CWE-79"}},
	}
	if c := Caveats(clean); len(c) != 0 {
		t.Errorf("a lone real XSS on HTTPS must produce no caveats; got %+v", c)
	}
}

func hasCaveat(cavs []Caveat, kind, substr string) bool {
	for _, c := range cavs {
		if c.Kind == kind && (strings.Contains(c.Title, substr) || strings.Contains(c.Detail, substr)) {
			return true
		}
	}
	return false
}
