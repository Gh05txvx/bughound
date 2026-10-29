package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"bughound/internal/finding"
	"bughound/internal/store"
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

func TestDashboardDeleteFindings(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()
	st.Save(ctx, mkWebFinding("acme", "run1", "ssrf", "https://acme.io/a", finding.SeverityCritical))
	st.Save(ctx, mkWebFinding("acme", "run1", "xss", "https://acme.io/b", finding.SeverityLow))
	st.Save(ctx, mkWebFinding("globex", "run1", "redir", "https://globex.io/c", finding.SeverityHigh))
	st.SaveProgram(ctx, store.Program{Name: "acme", InScope: []string{"acme.io"}}) // definisi scope harus bertahan

	// Baris bertemuan menampilkan tombol hapus.
	if b := do(t, srv, "GET", "/dashboard", nil).Body.String(); !strings.Contains(b, "hapus temuan") {
		t.Fatal("dashboard tak menampilkan tombol 'hapus temuan'")
	}

	rec := do(t, srv, "POST", "/dashboard/findings/delete", url.Values{"program": {"acme"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("hapus temuan = %d, ingin 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "ok=findings-deleted") || !strings.Contains(loc, "n=2") {
		t.Errorf("redirect harus membawa ok=findings-deleted & n=2, dapat %q", loc)
	}
	// Temuan acme habis; globex tetap; definisi scope acme tetap.
	if fs, _ := st.List(ctx, store.Query{Program: "acme"}); len(fs) != 0 {
		t.Errorf("temuan acme harus habis, sisa %d", len(fs))
	}
	if fs, _ := st.List(ctx, store.Query{Program: "globex"}); len(fs) != 1 {
		t.Errorf("temuan globex harus tetap, dapat %d", len(fs))
	}
	if _, err := st.GetProgram(ctx, "acme"); err != nil {
		t.Errorf("definisi scope acme harus tetap (hanya temuan dihapus): %v", err)
	}
	// Flash konfirmasi muncul.
	b := do(t, srv, "GET", "/dashboard?ok=findings-deleted&program=acme&n=2", nil).Body.String()
	if !strings.Contains(b, "temuan program") || !strings.Contains(b, "dihapus") {
		t.Error("flash hapus temuan tak muncul")
	}
}

func TestDashboardDeleteFindingsViewerForbidden(t *testing.T) {
	srv, st := newRBACServer(t)
	st.Save(context.Background(), mkWebFinding("keep", "r", "ssrf", "https://keep.io/a", finding.SeverityLow))
	csrf, sess := loginAs(t, srv, "view", "viewpw")
	if rec := authedReq(srv, "POST", "/dashboard/findings/delete", url.Values{"program": {"keep"}}, csrf, sess); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer POST /dashboard/findings/delete = %d, ingin 403", rec.Code)
	}
	if fs, _ := st.List(context.Background(), store.Query{Program: "keep"}); len(fs) != 1 {
		t.Error("temuan terhapus oleh viewer yang seharusnya ditolak")
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
