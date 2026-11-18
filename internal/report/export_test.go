package report

import (
	"strings"
	"testing"
	"time"

	"bughound/internal/finding"
)

func TestExportHackerOne(t *testing.T) {
	f := mk("SSRF at /fetch", finding.SeverityCritical, finding.StatusConfirmed)
	f.CWE = []string{"CWE-918"}
	f.Description = "The server fetches a URL from a parameter without validation."
	f.Reproduction = []string{"Send POST /fetch", "Observe the internal metadata response"}
	f.CVSS = &finding.CVSS{Score: 9.3, Vector: "CVSS:3.1/AV:N/AC:L"}

	md := ExportFinding(f, PlatformHackerOne)
	for _, want := range []string{
		"# SSRF at /fetch", draftNote, "## Summary", "## Steps To Reproduce",
		"## Impact", "Critical", "CWE-918", "https://demo.test/x",
		"Send POST /fetch", "CVSS:3.1", "Request:",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("the H1 export must contain %q\n---\n%s", want, md)
		}
	}
	if strings.Contains(md, "SECRET") { // evidence is redacted upstream
		t.Error("the export must not contain a raw secret")
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
			t.Errorf("severity %s must map to %s:\n%s", sev, want, md)
		}
		for _, sec := range []string{"Vulnerability Details", "Steps to Reproduce", "Impact", "Remediation"} {
			if !strings.Contains(md, sec) {
				t.Errorf("the Bugcrowd export (%s) must contain the %q section", sev, sec)
			}
		}
	}
}

func TestExportReportAllConfirmed(t *testing.T) {
	r := Build("demo", []*finding.Finding{
		mk("a", finding.SeverityCritical, finding.StatusConfirmed),
		mk("b", finding.SeverityLow, finding.StatusConfirmed),
		mk("c", finding.SeverityHigh, finding.StatusNew), // ignored (not confirmed)
	}, time.Now())

	md := ExportReport(r, PlatformHackerOne)
	if !strings.Contains(md, "# Export HackerOne — demo") || !strings.Contains(md, draftNote) {
		t.Error("the report export header is missing")
	}
	if n := strings.Count(md, "## Summary"); n != 2 {
		t.Errorf("there must be 2 formatted confirmed findings; got %d", n)
	}
}

func TestExportIncludesImpact(t *testing.T) {
	f := mk("x", finding.SeverityHigh, finding.StatusConfirmed)
	f.Impact = "An attacker reads internal cloud metadata."
	for _, p := range []Platform{PlatformHackerOne, PlatformBugcrowd} {
		if md := ExportFinding(f, p); !strings.Contains(md, f.Impact) {
			t.Errorf("the %s export must contain the impact text the hunter filled in:\n%s", p.Label(), md)
		}
	}
	// Without impact: the placeholder is still there (the Impact section is never empty).
	if md := ExportFinding(mk("y", finding.SeverityHigh, finding.StatusConfirmed), PlatformHackerOne); !strings.Contains(md, "Describe the concrete impact") {
		t.Errorf("without impact there must be a placeholder:\n%s", md)
	}
}

func TestPlatformValid(t *testing.T) {
	if !PlatformHackerOne.Valid() || !PlatformBugcrowd.Valid() {
		t.Error("the official platforms must be valid")
	}
	if Platform("jira").Valid() {
		t.Error("an unknown platform must be invalid")
	}
}
