package report

import (
	"strings"
	"testing"
	"time"

	"bughound/internal/finding"
)

func mk(title string, sev finding.Severity, status finding.Status) *finding.Finding {
	return &finding.Finding{
		ID: title, Program: "demo", RunID: "r", Target: "https://demo.test",
		Type: "ssrf", Title: title, Severity: sev, Confidence: finding.ConfidenceMedium,
		Status: status, SourceEngine: "nuclei",
		Location:  finding.Location{URL: "https://demo.test/x"},
		CreatedAt: finding.NewTime(time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC)),
		Evidence:  &finding.Evidence{Request: "GET /x HTTP/1.1\nAuthorization: [REDACTED]"},
	}
}

func TestBuildOnlyConfirmed(t *testing.T) {
	findings := []*finding.Finding{
		mk("a-confirmed", finding.SeverityHigh, finding.StatusConfirmed),
		mk("b-new", finding.SeverityCritical, finding.StatusNew),
		mk("c-fp", finding.SeverityHigh, finding.StatusFalsePositive),
		mk("d-confirmed", finding.SeverityCritical, finding.StatusConfirmed),
	}
	r := Build("demo", findings, time.Now())
	if len(r.Items) != 2 {
		t.Fatalf("only confirmed findings go in; got %d", len(r.Items))
	}
	// Sorted by severity: critical first.
	if r.Items[0].Title != "d-confirmed" {
		t.Errorf("critical must be on top; got %s", r.Items[0].Title)
	}
}

func TestBuildMarkdown(t *testing.T) {
	r := Build("demo", []*finding.Finding{mk("SSRF at /x", finding.SeverityCritical, finding.StatusConfirmed)}, time.Now())
	md := r.Markdown
	for _, want := range []string{"# Report: demo", "DRAFT", "SSRF at /x", "critical", "## Findings", "Request:"} {
		if !strings.Contains(md, want) {
			t.Errorf("the markdown must contain %q", want)
		}
	}
	// The evidence is already redacted in the store; the report must not leak it.
	if strings.Contains(md, "SECRET") {
		t.Error("the markdown must not contain a raw secret")
	}
}

func TestBuildMarkdownImpact(t *testing.T) {
	f := mk("SSRF at /x", finding.SeverityCritical, finding.StatusConfirmed)
	f.Impact = "An attacker reads internal cloud metadata (SSRF)."
	r := Build("demo", []*finding.Finding{f}, time.Now())
	if !strings.Contains(r.Markdown, "**Impact:**") || !strings.Contains(r.Markdown, f.Impact) {
		t.Errorf("the markdown must contain the Impact section the hunter filled in:\n%s", r.Markdown)
	}
}

func TestBuildEmpty(t *testing.T) {
	r := Build("demo", []*finding.Finding{mk("x", finding.SeverityLow, finding.StatusNew)}, time.Now())
	if len(r.Items) != 0 {
		t.Fatal("without confirmed findings, Items must be empty")
	}
	if !strings.Contains(r.Markdown, "No confirmed findings yet") {
		t.Error("an empty markdown must state that there are no confirmed findings")
	}
}
