package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

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
	// The dashboard UI puts the KPI numbers & their labels in separate stat-card elements
	// (not an "N programs" phrase): check the label + KPI value, the program row, and the
	// "of 3 findings" sub on the Confirmed card.
	for _, want := range []string{
		"acme", "globex", "3 findings",
		`<span class="sc-label">Programs</span>`, `<div class="sc-kpi">2</div>`, // 2 program
		`<span class="sc-label">Confirmed</span>`, `<div class="sc-kpi">1</div>`, // 1 confirmed
	} {
		if !strings.Contains(b, want) {
			t.Errorf("the dashboard must contain %q", want)
		}
	}
}

func TestDashboardEmpty(t *testing.T) {
	srv, _ := newTestServer(t)
	b := do(t, srv, "GET", "/dashboard", nil).Body.String()
	if !strings.Contains(b, "No programs") {
		t.Errorf("the empty dashboard must guide the user:\n%s", b)
	}
}

func TestDashboardDeleteFindings(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()
	st.Save(ctx, mkWebFinding("acme", "run1", "ssrf", "https://acme.io/a", finding.SeverityCritical))
	st.Save(ctx, mkWebFinding("acme", "run1", "xss", "https://acme.io/b", finding.SeverityLow))
	st.Save(ctx, mkWebFinding("globex", "run1", "redir", "https://globex.io/c", finding.SeverityHigh))
	st.SaveProgram(ctx, store.Program{Name: "acme", InScope: []string{"acme.io"}}) // the scope definition must persist

	// A row with findings shows the delete button.
	if b := do(t, srv, "GET", "/dashboard", nil).Body.String(); !strings.Contains(b, "delete findings") {
		t.Fatal("the dashboard does not show the 'delete findings' button")
	}

	rec := do(t, srv, "POST", "/dashboard/findings/delete", url.Values{"program": {"acme"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("delete findings = %d, want 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "ok=findings-deleted") || !strings.Contains(loc, "n=2") {
		t.Errorf("the redirect must carry ok=findings-deleted & n=2, got %q", loc)
	}
	// acme findings are gone; globex stays; the acme scope definition stays.
	if fs, _ := st.List(ctx, store.Query{Program: "acme"}); len(fs) != 0 {
		t.Errorf("acme findings must be gone, %d left", len(fs))
	}
	if fs, _ := st.List(ctx, store.Query{Program: "globex"}); len(fs) != 1 {
		t.Errorf("globex findings must stay, got %d", len(fs))
	}
	if _, err := st.GetProgram(ctx, "acme"); err != nil {
		t.Errorf("the acme scope definition must stay (only findings deleted): %v", err)
	}
	// The confirmation flash shows up.
	b := do(t, srv, "GET", "/dashboard?ok=findings-deleted&program=acme&n=2", nil).Body.String()
	if !strings.Contains(b, "findings of program") || !strings.Contains(b, "deleted") {
		t.Error("the delete-findings flash did not show")
	}
}

// TestDashboardDeleteFindingsPurgesAICache makes sure deleting a program's
// findings also drops its AI analysis cache (no orphan rows), while
// another program's cache stays intact.
func TestDashboardDeleteFindingsPurgesAICache(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()
	fa, _ := st.Save(ctx, mkWebFinding("acme", "run1", "ssrf", "https://acme.io/a", finding.SeverityCritical))
	fg, _ := st.Save(ctx, mkWebFinding("globex", "run1", "redir", "https://globex.io/c", finding.SeverityHigh))

	for _, a := range []store.AIAnalysis{
		{FindingID: fa.ID, Program: "acme", Model: "m", SourceHash: "h", Payload: "{}"},
		{FindingID: fg.ID, Program: "globex", Model: "m", SourceHash: "h", Payload: "{}"},
	} {
		if err := st.PutAIAnalysis(ctx, a); err != nil {
			t.Fatal(err)
		}
	}

	if rec := do(t, srv, "POST", "/dashboard/findings/delete", url.Values{"program": {"acme"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("delete findings = %d, want 303", rec.Code)
	}
	if _, err := st.GetAIAnalysis(ctx, fa.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("the acme AI cache must be dropped with its findings, got err=%v", err)
	}
	if _, err := st.GetAIAnalysis(ctx, fg.ID); err != nil {
		t.Errorf("the globex AI cache must not be deleted too: %v", err)
	}
}

func TestDashboardDeleteFindingsViewerForbidden(t *testing.T) {
	srv, st := newRBACServer(t)
	st.Save(context.Background(), mkWebFinding("keep", "r", "ssrf", "https://keep.io/a", finding.SeverityLow))
	csrf, sess := loginAs(t, srv, "view", "viewpw")
	if rec := authedReq(srv, "POST", "/dashboard/findings/delete", url.Values{"program": {"keep"}}, csrf, sess); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer POST /dashboard/findings/delete = %d, want 403", rec.Code)
	}
	if fs, _ := st.List(context.Background(), store.Query{Program: "keep"}); len(fs) != 1 {
		t.Error("findings deleted by a viewer that should have been denied")
	}
}

func TestDashboardScansLive(t *testing.T) {
	srv, _ := newTestServer(t)

	// Empty: the partial shows the empty state; the dashboard embeds the loader.
	empty := do(t, srv, "GET", "/dashboard/scans", nil)
	if empty.Code != http.StatusOK {
		t.Fatalf("GET /dashboard/scans = %d", empty.Code)
	}
	if b := empty.Body.String(); !strings.Contains(b, "No scans") || !strings.Contains(b, `id="live-scans"`) {
		t.Errorf("the empty partial does not match:\n%s", b)
	}
	if b := do(t, srv, "GET", "/dashboard", nil).Body.String(); !strings.Contains(b, `hx-get="/dashboard/scans"`) {
		t.Error("the dashboard does not embed the live-scans loader")
	}

	// Run one scan (mock engine) to completion → it shows up in the monitor.
	rec := do(t, srv, "POST", "/scan", url.Values{"program": {"live-demo"}, "in_scope": {"demo.test"}, "targets": {"demo.test"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /scan = %d", rec.Code)
	}
	waitRunDone(t, srv, runIDFrom(t, rec.Body.String()))

	b := do(t, srv, "GET", "/dashboard/scans", nil).Body.String()
	if !strings.Contains(b, "live-demo") || !strings.Contains(b, "done") {
		t.Errorf("the live monitor does not show the finished run:\n%s", b)
	}
	// All runs are finished → idle polling (the slow 6s interval).
	if !strings.Contains(b, "delay:6s") {
		t.Errorf("the idle polling interval must be 6s:\n%s", b)
	}
}

func TestHumanDur(t *testing.T) {
	for _, c := range []struct {
		d    time.Duration
		want string
	}{
		{500 * time.Millisecond, "<1s"},
		{9 * time.Second, "9s"},
		{65 * time.Second, "1m 05s"},
		{2*time.Hour + 10*time.Minute, "2h 10m"},
	} {
		if got := humanDur(c.d); got != c.want {
			t.Errorf("humanDur(%v) = %q, want %q", c.d, got, c.want)
		}
	}
}

// Root redirects to the dashboard.
func TestRootRedirectsToDashboard(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := do(t, srv, "GET", "/", nil)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/dashboard" {
		t.Fatalf("GET / must redirect to /dashboard; got %d -> %q", rec.Code, rec.Header().Get("Location"))
	}
}
