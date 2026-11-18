package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"bughound/internal/finding"
)

func TestReportExportPlatforms(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()

	// One confirmed finding to export.
	r, _ := st.Save(ctx, mkWebFinding("acme", "run1", "ssrf", "https://acme.io/a", finding.SeverityCritical))
	if err := st.SetStatus(ctx, r.ID, finding.StatusConfirmed, "tester"); err != nil {
		t.Fatal(err)
	}

	// Export the whole report (HackerOne), markdown, with the template sections.
	rec := do(t, srv, "GET", "/report/export?program=acme&platform=hackerone", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("export H1 = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "markdown") {
		t.Errorf("content-type must be markdown; got %q", ct)
	}
	if b := rec.Body.String(); !strings.Contains(b, "Export HackerOne — acme") || !strings.Contains(b, "## Summary") {
		t.Errorf("the H1 report export is missing content:\n%s", b)
	}

	// Per-finding export (Bugcrowd), critical -> P1.
	rec = do(t, srv, "GET", "/report/export?program=acme&platform=bugcrowd&id="+url.QueryEscape(r.ID), nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "P1") {
		t.Errorf("the per-finding Bugcrowd export failed: %d\n%s", rec.Code, rec.Body.String())
	}

	// Unknown platform -> 400 (fail-closed).
	if rec := do(t, srv, "GET", "/report/export?program=acme&platform=jira", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("an unknown platform must be 400; got %d", rec.Code)
	}

	// A non-confirmed finding must not be exported -> 400.
	r2, _ := st.Save(ctx, mkWebFinding("acme", "run1", "xss", "https://acme.io/b", finding.SeverityLow))
	if rec := do(t, srv, "GET", "/report/export?program=acme&platform=hackerone&id="+url.QueryEscape(r2.ID), nil); rec.Code != http.StatusBadRequest {
		t.Errorf("exporting a non-confirmed finding must be 400; got %d", rec.Code)
	}
}
