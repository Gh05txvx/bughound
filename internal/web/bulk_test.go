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
		Title:        typ + " di " + locURL,
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

	// Filter severity=critical hanya menampilkan ssrf.
	b := do(t, srv, "GET", "/findings?program=acme&severity=critical", nil).Body.String()
	if !strings.Contains(b, "ssrf") || strings.Contains(b, "xss") || strings.Contains(b, "redir") {
		t.Errorf("filter severity gagal menyaring:\n%s", b)
	}

	// Filter type=xss hanya menampilkan xss.
	b = do(t, srv, "GET", "/findings?program=acme&type=xss", nil).Body.String()
	if !strings.Contains(b, "xss") || strings.Contains(b, "ssrf") || strings.Contains(b, "redir") {
		t.Errorf("filter type gagal menyaring:\n%s", b)
	}

	// Filter run=run2 hanya menampilkan redir.
	b = do(t, srv, "GET", "/findings?program=acme&run=run2", nil).Body.String()
	if !strings.Contains(b, "redir") || strings.Contains(b, "ssrf") {
		t.Errorf("filter run gagal menyaring:\n%s", b)
	}

	// Aksi massal: konfirmasi f1 & f3, biarkan f2 tak tersentuh.
	rec := do(t, srv, "POST", "/findings/bulk", url.Values{
		"program": {"acme"}, "status": {"confirmed"},
		"ids": {r1.ID, r3.ID},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("bulk triage = %d, ingin 303", rec.Code)
	}
	if f, _ := st.Get(ctx, r1.ID); f.Status != finding.StatusConfirmed {
		t.Errorf("f1 harus confirmed, dapat %q", f.Status)
	}
	if f, _ := st.Get(ctx, r3.ID); f.Status != finding.StatusConfirmed {
		t.Errorf("f3 harus confirmed, dapat %q", f.Status)
	}
	if f, _ := st.Get(ctx, r2.ID); f.Status != finding.StatusNew {
		t.Errorf("f2 harus tetap new, dapat %q", f.Status)
	}

	// Status triase tak dikenal ditolak (fail-closed), tak mengubah apa pun.
	rec = do(t, srv, "POST", "/findings/bulk", url.Values{
		"program": {"acme"}, "status": {"bogus"}, "ids": {r2.ID},
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status tak dikenal harus 400, dapat %d", rec.Code)
	}
	if f, _ := st.Get(ctx, r2.ID); f.Status != finding.StatusNew {
		t.Errorf("f2 tak boleh berubah oleh status tak valid, dapat %q", f.Status)
	}
}
