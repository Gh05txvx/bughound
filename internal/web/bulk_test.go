package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"bughound/internal/finding"
)

func mkWebFinding(program, runID, typ, locURL string, sev finding.Severity) *finding.Finding {
	return &finding.Finding{
		Program:      program,
		RunID:        runID,
		Target:       "https://acme.io",
		Type:         typ,
		Title:        typ + " at " + locURL,
		Severity:     sev,
		Confidence:   finding.ConfidenceMedium,
		Status:       finding.StatusNew,
		SourceEngine: "nuclei",
		Location:     finding.Location{URL: locURL, Parameter: "q"},
	}
}

func TestFindingsFilterAndBulkTriage(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()

	r1, _ := st.Save(ctx, mkWebFinding("acme", "run1", "ssrf", "https://acme.io/a", finding.SeverityCritical))
	r2, _ := st.Save(ctx, mkWebFinding("acme", "run1", "xss", "https://acme.io/b", finding.SeverityLow))
	r3, _ := st.Save(ctx, mkWebFinding("acme", "run2", "redir", "https://acme.io/c", finding.SeverityHigh))

	// Filter severity=critical shows only ssrf.
	b := do(t, srv, "GET", "/findings?program=acme&severity=critical", nil).Body.String()
	if !strings.Contains(b, "ssrf") || strings.Contains(b, "xss") || strings.Contains(b, "redir") {
		t.Errorf("the severity filter failed to filter:\n%s", b)
	}

	// Filter type=xss shows only xss.
	b = do(t, srv, "GET", "/findings?program=acme&type=xss", nil).Body.String()
	if !strings.Contains(b, "xss") || strings.Contains(b, "ssrf") || strings.Contains(b, "redir") {
		t.Errorf("the type filter failed to filter:\n%s", b)
	}

	// Filter run=run2 shows only redir.
	b = do(t, srv, "GET", "/findings?program=acme&run=run2", nil).Body.String()
	if !strings.Contains(b, "redir") || strings.Contains(b, "ssrf") {
		t.Errorf("the run filter failed to filter:\n%s", b)
	}

	// Bulk action: confirm f1 & f3, leave f2 untouched.
	rec := do(t, srv, "POST", "/findings/bulk", url.Values{
		"program": {"acme"}, "status": {"confirmed"},
		"ids": {r1.ID, r3.ID},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("bulk triage = %d, want 303", rec.Code)
	}
	if f, _ := st.Get(ctx, r1.ID); f.Status != finding.StatusConfirmed {
		t.Errorf("f1 must be confirmed, got %q", f.Status)
	}
	if f, _ := st.Get(ctx, r3.ID); f.Status != finding.StatusConfirmed {
		t.Errorf("f3 must be confirmed, got %q", f.Status)
	}
	if f, _ := st.Get(ctx, r2.ID); f.Status != finding.StatusNew {
		t.Errorf("f2 must stay new, got %q", f.Status)
	}

	// An unknown triage status is rejected (fail-closed), changing nothing.
	rec = do(t, srv, "POST", "/findings/bulk", url.Values{
		"program": {"acme"}, "status": {"bogus"}, "ids": {r2.ID},
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("an unknown status must be 400, got %d", rec.Code)
	}
	if f, _ := st.Get(ctx, r2.ID); f.Status != finding.StatusNew {
		t.Errorf("f2 must not change on an invalid status, got %q", f.Status)
	}
}
