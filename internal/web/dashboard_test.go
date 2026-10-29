package web

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"bughound/internal/finding"
)

func TestDashboardSummary(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()

	ca, _ := st.Save(ctx, mkWebFinding("acme", "run1", "ssrf", "https://acme.io/a", finding.SeverityCritical))
	st.Save(ctx, mkWebFinding("acme", "run1", "xss", "https://acme.io/b", finding.SeverityLow))
	st.Save(ctx, mkWebFinding("globex", "run1", "redir", "https://globex.io/c", finding.SeverityHigh))
	if err := st.SetStatus(ctx, ca.ID, finding.StatusConfirmed, "t"); err != nil {
		t.Fatal(err)
	}

	rec := do(t, srv, "GET", "/dashboard", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /dashboard = %d", rec.Code)
	}
	b := rec.Body.String()
	// UI dashboard menaruh angka KPI & labelnya di elemen stat-card terpisah
	// (bukan frasa "N program"): cek label + nilai KPI, baris program, dan sub
	// "dari 3 temuan" pada kartu Terkonfirmasi.
	for _, want := range []string{
		"acme", "globex", "3 temuan",
		`<span class="sc-label">Programs</span>`, `<div class="sc-kpi">2</div>`, // 2 program
		`<span class="sc-label">Terkonfirmasi</span>`, `<div class="sc-kpi">1</div>`, // 1 terkonfirmasi
	} {
		if !strings.Contains(b, want) {
			t.Errorf("dashboard harus memuat %q", want)
		}
	}
}

func TestDashboardEmpty(t *testing.T) {
	srv, _ := newTestServer(t)
	b := do(t, srv, "GET", "/dashboard", nil).Body.String()
	if !strings.Contains(b, "Belum ada program") {
		t.Errorf("dashboard kosong harus mengarahkan pengguna:\n%s", b)
	}
}

// Root mengarahkan ke dashboard.
func TestRootRedirectsToDashboard(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := do(t, srv, "GET", "/", nil)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/dashboard" {
		t.Fatalf("GET / harus redirect ke /dashboard; dapat %d -> %q", rec.Code, rec.Header().Get("Location"))
	}
}
