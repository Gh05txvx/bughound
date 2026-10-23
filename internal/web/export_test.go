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

	// Satu temuan terkonfirmasi untuk diekspor.
	r, _ := st.Save(ctx, mkWebFinding("acme", "run1", "ssrf", "https://acme.io/a", finding.SeverityCritical))
	if err := st.SetStatus(ctx, r.ID, finding.StatusConfirmed, "tester"); err != nil {
		t.Fatal(err)
	}

	// Export seluruh report (HackerOne) — markdown, berisi bagian template.
	rec := do(t, srv, "GET", "/report/export?program=acme&platform=hackerone", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("export H1 = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "markdown") {
		t.Errorf("content-type harus markdown; dapat %q", ct)
	}
	if b := rec.Body.String(); !strings.Contains(b, "Export HackerOne — acme") || !strings.Contains(b, "## Summary") {
		t.Errorf("export report H1 kurang isi:\n%s", b)
	}

	// Export per-temuan (Bugcrowd) — critical -> P1.
	rec = do(t, srv, "GET", "/report/export?program=acme&platform=bugcrowd&id="+url.QueryEscape(r.ID), nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "P1") {
		t.Errorf("export per-temuan Bugcrowd gagal: %d\n%s", rec.Code, rec.Body.String())
	}

	// Platform tak dikenal -> 400 (fail-closed).
	if rec := do(t, srv, "GET", "/report/export?program=acme&platform=jira", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("platform tak dikenal harus 400; dapat %d", rec.Code)
	}

	// Temuan non-confirmed tak boleh diekspor -> 400.
	r2, _ := st.Save(ctx, mkWebFinding("acme", "run1", "xss", "https://acme.io/b", finding.SeverityLow))
	if rec := do(t, srv, "GET", "/report/export?program=acme&platform=hackerone&id="+url.QueryEscape(r2.ID), nil); rec.Code != http.StatusBadRequest {
		t.Errorf("export temuan non-confirmed harus 400; dapat %d", rec.Code)
	}
}
