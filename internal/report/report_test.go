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
		t.Fatalf("hanya confirmed yang masuk; dapat %d", len(r.Items))
	}
	// Terurut severity: critical dulu.
	if r.Items[0].Title != "d-confirmed" {
		t.Errorf("critical harus di atas; dapat %s", r.Items[0].Title)
	}
}

func TestBuildMarkdown(t *testing.T) {
	r := Build("demo", []*finding.Finding{mk("SSRF di /x", finding.SeverityCritical, finding.StatusConfirmed)}, time.Now())
	md := r.Markdown
	for _, want := range []string{"# Laporan — demo", "DRAFT", "SSRF di /x", "critical", "## Temuan", "Request:"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown harus memuat %q", want)
		}
	}
	// Bukti sudah tersensor di store; report tidak boleh membocorkan.
	if strings.Contains(md, "SECRET") {
		t.Error("markdown tak boleh memuat secret mentah")
	}
}

func TestBuildEmpty(t *testing.T) {
	r := Build("demo", []*finding.Finding{mk("x", finding.SeverityLow, finding.StatusNew)}, time.Now())
	if len(r.Items) != 0 {
		t.Fatal("tanpa confirmed, Items harus kosong")
	}
	if !strings.Contains(r.Markdown, "Belum ada temuan terkonfirmasi") {
		t.Error("markdown kosong harus menyatakan tidak ada temuan terkonfirmasi")
	}
}
