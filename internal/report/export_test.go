package report

import (
	"strings"
	"testing"
	"time"

	"bughound/internal/finding"
)

func TestExportHackerOne(t *testing.T) {
	f := mk("SSRF di /fetch", finding.SeverityCritical, finding.StatusConfirmed)
	f.CWE = []string{"CWE-918"}
	f.Description = "Server mengambil URL dari parameter tanpa validasi."
	f.Reproduction = []string{"Kirim POST /fetch", "Amati respons metadata internal"}
	f.CVSS = &finding.CVSS{Score: 9.3, Vector: "CVSS:3.1/AV:N/AC:L"}

	md := ExportFinding(f, PlatformHackerOne)
	for _, want := range []string{
		"# SSRF di /fetch", draftNote, "## Summary", "## Steps To Reproduce",
		"## Impact", "Critical", "CWE-918", "https://demo.test/x",
		"Kirim POST /fetch", "CVSS:3.1", "Request:",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("export H1 harus memuat %q\n---\n%s", want, md)
		}
	}
	if strings.Contains(md, "SECRET") { // evidence tersensor di hulu
		t.Error("export tak boleh memuat secret mentah")
	}
}

func TestExportBugcrowdPriorityMapping(t *testing.T) {
	cases := map[finding.Severity]string{
		finding.SeverityCritical: "P1",
		finding.SeverityHigh:     "P2",
		finding.SeverityMedium:   "P3",
		finding.SeverityLow:      "P4",
		finding.SeverityInfo:     "P5",
	}
	for sev, want := range cases {
		f := mk("x", sev, finding.StatusConfirmed)
		md := ExportFinding(f, PlatformBugcrowd)
		if !strings.Contains(md, want) {
			t.Errorf("severity %s harus memetakan ke %s:\n%s", sev, want, md)
		}
		for _, sec := range []string{"Vulnerability Details", "Steps to Reproduce", "Impact", "Remediation"} {
			if !strings.Contains(md, sec) {
				t.Errorf("export Bugcrowd (%s) harus memuat bagian %q", sev, sec)
			}
		}
	}
}

func TestExportReportAllConfirmed(t *testing.T) {
	r := Build("demo", []*finding.Finding{
		mk("a", finding.SeverityCritical, finding.StatusConfirmed),
		mk("b", finding.SeverityLow, finding.StatusConfirmed),
		mk("c", finding.SeverityHigh, finding.StatusNew), // diabaikan (bukan confirmed)
	}, time.Now())

	md := ExportReport(r, PlatformHackerOne)
	if !strings.Contains(md, "# Export HackerOne — demo") || !strings.Contains(md, draftNote) {
		t.Error("header export report kurang")
	}
	if n := strings.Count(md, "## Summary"); n != 2 {
		t.Errorf("harus 2 temuan terkonfirmasi terformat; dapat %d", n)
	}
}

func TestExportIncludesImpact(t *testing.T) {
	f := mk("x", finding.SeverityHigh, finding.StatusConfirmed)
	f.Impact = "Penyerang membaca metadata internal cloud."
	for _, p := range Platforms() {
		if md := ExportFinding(f, p); !strings.Contains(md, f.Impact) {
			t.Errorf("export %s harus memuat teks dampak yang diisi hunter:\n%s", p.Label(), md)
		}
	}
	// Tanpa impact: placeholder tetap ada (bagian Impact tak pernah kosong).
	if md := ExportFinding(mk("y", finding.SeverityHigh, finding.StatusConfirmed), PlatformHackerOne); !strings.Contains(md, "Jelaskan dampak") {
		t.Errorf("tanpa impact harus ada placeholder:\n%s", md)
	}
}

func TestPlatformValid(t *testing.T) {
	if !PlatformHackerOne.Valid() || !PlatformBugcrowd.Valid() {
		t.Error("platform resmi harus valid")
	}
	if Platform("jira").Valid() {
		t.Error("platform tak dikenal harus invalid")
	}
}
