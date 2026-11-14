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
		wantAny []string // minimal satu harus muncul di gabungan butir
	}{
		{"sqli", "sqli", []string{"CWE-89"}, []string{"parameterized", "prepared"}},
		{"xss", "xss-reflected", []string{"CWE-79"}, []string{"Encode", "Content-Security-Policy"}},
		{"ssrf", "ssrf", []string{"CWE-918"}, []string{"allowlist", "metadata"}},
		{"ssti", "ssti", []string{"CWE-1336"}, []string{"template", "sandbox"}},
		{"xxe", "xxe", []string{"CWE-611"}, []string{"external entity", "DTD"}},
		{"idor", "idor", []string{"CWE-639"}, []string{"otorisasi tingkat-objek", "default-deny"}},
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
				t.Errorf("%s: remediasi tak menyebut salah satu dari %v:\n%s", c.name, c.wantAny, got)
			}
		})
	}
}

func TestRemediationOWASPFallback(t *testing.T) {
	// Type tak dikenal → fallback ke kategori OWASP.
	got := strings.ToLower(strings.Join(remediationFor(&finding.Finding{Type: "sesuatu-aneh", OWASP: finding.A05}), " "))
	if !strings.Contains(got, "konfigurasi") {
		t.Errorf("fallback A05 harus menyebut konfigurasi:\n%s", got)
	}
}

func TestRemediationAlwaysNonEmpty(t *testing.T) {
	// Tanpa type, CWE, OWASP → tetap ada panduan generik non-kosong.
	if got := remediationFor(&finding.Finding{}); len(got) == 0 || strings.TrimSpace(got[0]) == "" {
		t.Errorf("remediasi tak boleh kosong: %v", got)
	}
}

func TestExportIncludesRemediation(t *testing.T) {
	f := mk("SQLi di /search", finding.SeverityHigh, finding.StatusConfirmed)
	f.Type = "sqli"
	f.CWE = []string{"CWE-89"}
	f.References = []string{"https://owasp.org/Top10/A03_2021-Injection/"}

	// HackerOne: bagian Remediation + butir spesifik-kelas + References terpisah.
	h1 := ExportFinding(f, PlatformHackerOne)
	if !strings.Contains(h1, "## Remediation") {
		t.Errorf("H1 harus punya bagian Remediation:\n%s", h1)
	}
	if !strings.Contains(h1, "parameterized") && !strings.Contains(h1, "prepared") {
		t.Errorf("H1 remediasi SQLi harus actionable:\n%s", h1)
	}
	if !strings.Contains(h1, "References") {
		t.Errorf("H1 harus tetap punya bagian References:\n%s", h1)
	}

	// Bugcrowd: Remediation actionable + References jadi bagian sendiri, Remediation lebih dulu.
	bc := ExportFinding(f, PlatformBugcrowd)
	ri, fi := strings.Index(bc, "**Remediation**"), strings.Index(bc, "**References**")
	if ri < 0 || fi < 0 {
		t.Errorf("Bugcrowd harus pisahkan Remediation & References:\n%s", bc)
	}
	if ri > fi {
		t.Errorf("Remediation harus sebelum References di Bugcrowd:\n%s", bc)
	}
}
