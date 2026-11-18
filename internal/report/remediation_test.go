package report

import (
	"strings"
	"testing"

	"bughound/internal/finding"
)

func TestRemediationByClass(t *testing.T) {
	cases := []struct {
		name    string
		typ     string
		cwe     []string
		wantAny []string // at least one must appear in the joined items
	}{
		{"sqli", "sqli", []string{"CWE-89"}, []string{"parameterized", "prepared"}},
		{"xss", "xss-reflected", []string{"CWE-79"}, []string{"Encode", "Content-Security-Policy"}},
		{"ssrf", "ssrf", []string{"CWE-918"}, []string{"allowlist", "metadata"}},
		{"ssti", "ssti", []string{"CWE-1336"}, []string{"template", "sandbox"}},
		{"xxe", "xxe", []string{"CWE-611"}, []string{"external entity", "DTD"}},
		{"idor", "idor", []string{"CWE-639"}, []string{"object-level authorization", "default deny"}},
		{"open-redirect", "open-redirect", []string{"CWE-601"}, []string{"allowlist", "interstitial"}},
		{"rce-hyphen", "os-command-injection", nil, []string{"shell", "array"}},
		{"jwt", "jwt-alg-none", []string{"CWE-347"}, []string{"alg", "signature"}},
		{"upload-hyphen", "file-upload", nil, []string{"magic bytes", "webroot"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := strings.Join(remediationFor(&finding.Finding{Type: c.typ, CWE: c.cwe}), " ")
			ok := false
			for _, w := range c.wantAny {
				if strings.Contains(got, w) {
					ok = true
					break
				}
			}
			if !ok {
				t.Errorf("%s: the remediation mentions none of %v:\n%s", c.name, c.wantAny, got)
			}
		})
	}
}

func TestRemediationOWASPFallback(t *testing.T) {
	// Unknown type → falls back to the OWASP category.
	got := strings.ToLower(strings.Join(remediationFor(&finding.Finding{Type: "something-odd", OWASP: finding.A05}), " "))
	if !strings.Contains(got, "configuration") {
		t.Errorf("the A05 fallback must mention configuration:\n%s", got)
	}
}

func TestRemediationAlwaysNonEmpty(t *testing.T) {
	// No type, CWE or OWASP → there is still non-empty generic guidance.
	if got := remediationFor(&finding.Finding{}); len(got) == 0 || strings.TrimSpace(got[0]) == "" {
		t.Errorf("the remediation must not be empty: %v", got)
	}
}

func TestExportIncludesRemediation(t *testing.T) {
	f := mk("SQLi at /search", finding.SeverityHigh, finding.StatusConfirmed)
	f.Type = "sqli"
	f.CWE = []string{"CWE-89"}
	f.References = []string{"https://owasp.org/Top10/A03_2021-Injection/"}

	// HackerOne: a Remediation section + class-specific items + a separate References section.
	h1 := ExportFinding(f, PlatformHackerOne)
	if !strings.Contains(h1, "## Remediation") {
		t.Errorf("H1 must have a Remediation section:\n%s", h1)
	}
	if !strings.Contains(h1, "parameterized") && !strings.Contains(h1, "prepared") {
		t.Errorf("the H1 SQLi remediation must be actionable:\n%s", h1)
	}
	if !strings.Contains(h1, "References") {
		t.Errorf("H1 must still have a References section:\n%s", h1)
	}

	// Bugcrowd: actionable Remediation + References as its own section, Remediation first.
	bc := ExportFinding(f, PlatformBugcrowd)
	ri, fi := strings.Index(bc, "**Remediation**"), strings.Index(bc, "**References**")
	if ri < 0 || fi < 0 {
		t.Errorf("Bugcrowd must separate Remediation and References:\n%s", bc)
	}
	if ri > fi {
		t.Errorf("Remediation must come before References in Bugcrowd:\n%s", bc)
	}
}
