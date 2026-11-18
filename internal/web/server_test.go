package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"bughound/internal/audit"
	"bughound/internal/engine"
	"bughound/internal/engine/ffuf"
	"bughound/internal/engine/nuclei"
	"bughound/internal/finding"
	"bughound/internal/recon"
	"bughound/internal/secret"
	"bughound/internal/store"
)

func newTestServer(t *testing.T) (*Server, *store.Mem) {
	t.Helper()
	st := store.NewMem()
	k, _ := secret.NewRandomKey()
	srv, err := NewServer(Config{
		Store:        st,
		Engines:      []engine.Engine{nuclei.Mock{}, ffuf.Mock{}},
		Recon:        recon.MockPipeline{},
		Vault:        secret.NewMemVault(secret.NewKeyring(k)),
		Audit:        audit.NewMemLog([]byte("test-audit-key")),
		AuthDisabled: true, // the feature is tested without a login gate; RBAC is tested separately
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv, st
}

// runIDFrom extracts the run id from the status partial (id="run-...").
func runIDFrom(t *testing.T, body string) string {
	t.Helper()
	m := regexp.MustCompile(`id="run-([^"]+)"`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("run id not found in the response:\n%s", body)
	}
	return m[1]
}

// waitRunDone waits for the run to reach a terminal state, then returns its body.
func waitRunDone(t *testing.T, srv *Server, id string) string {
	t.Helper()
	for i := 0; i < 300; i++ {
		b := do(t, srv, "GET", "/runs/"+id, nil).Body.String()
		if strings.Contains(b, "View findings") || strings.Contains(b, "failed") {
			return b
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the run did not finish in time")
	return ""
}

func do(t *testing.T, srv *Server, method, target string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	// For a state-changing request, take the CSRF token first (double-submit).
	var token string
	if method != http.MethodGet && method != http.MethodHead {
		gr := httptest.NewRecorder()
		srv.ServeHTTP(gr, httptest.NewRequest(http.MethodGet, "/scan", nil))
		for _, c := range gr.Result().Cookies() {
			if c.Name == csrfCookie {
				token = c.Value
			}
		}
	}
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	req := httptest.NewRequest(method, target, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if token != "" {
		req.AddCookie(&http.Cookie{Name: csrfCookie, Value: token})
		req.Header.Set("X-CSRF-Token", token)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func TestScanFormRenders(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := do(t, srv, "GET", "/scan", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /scan = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Scan configuration") || !strings.Contains(body, "demo.test") {
		t.Error("the scan form did not render with the prefill")
	}
}

func TestStaticServed(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := do(t, srv, "GET", "/static/app.css", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /static/app.css = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "css") {
		t.Errorf("css content-type expected, got %q", ct)
	}
}

func TestScanRunThenFindings(t *testing.T) {
	srv, st := newTestServer(t)

	rec := do(t, srv, "POST", "/scan", url.Values{
		"program": {"demo"}, "in_scope": {"demo.test"}, "targets": {"demo.test\nevil.test"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /scan = %d", rec.Code)
	}
	done := waitRunDone(t, srv, runIDFrom(t, rec.Body.String()))
	if !strings.Contains(done, "new findings") || !strings.Contains(done, "evil.test") {
		t.Errorf("the finished run status is missing the summary/denial:\n%s", done)
	}

	fs, _ := st.List(context.Background(), store.Query{Program: "demo"})
	var hasNuclei, hasFfuf bool
	for _, f := range fs {
		switch f.SourceEngine {
		case "nuclei":
			hasNuclei = true
		case "ffuf":
			hasFfuf = true
		}
	}
	if !hasNuclei || !hasFfuf {
		t.Fatalf("both engines (nuclei+ffuf) must contribute; got %d findings", len(fs))
	}

	rec = do(t, srv, "GET", "/findings?program=demo", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "ssrf-via-fetch") {
		t.Errorf("findings does not show the finding (code=%d)", rec.Code)
	}

	rec = do(t, srv, "GET", "/findings/"+fs[0].ID+"?program=demo", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET detail = %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "SECRET-abc123") {
		t.Error("the detail leaks the secret")
	}
}

func TestTriageConfirm(t *testing.T) {
	srv, st := newTestServer(t)
	rec0 := do(t, srv, "POST", "/scan", url.Values{
		"program": {"demo"}, "in_scope": {"demo.test"}, "targets": {"demo.test"},
	})
	waitRunDone(t, srv, runIDFrom(t, rec0.Body.String()))
	fs, _ := st.List(context.Background(), store.Query{Program: "demo"})
	if len(fs) == 0 {
		t.Fatal("no finding to triage")
	}
	id := fs[0].ID

	rec := do(t, srv, "POST", "/findings/"+id+"/status", url.Values{
		"status":      {"confirmed"},
		"verified_by": {"gh05t"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST status = %d", rec.Code)
	}
	got, _ := st.Get(context.Background(), id)
	if got.Status != "confirmed" || got.VerifiedBy != "gh05t" {
		t.Errorf("triage not stored: status=%s by=%s", got.Status, got.VerifiedBy)
	}

	// Manual triage must not set duplicate.
	rec = do(t, srv, "POST", "/findings/"+id+"/status", url.Values{"status": {"duplicate"}})
	if rec.Code == http.StatusOK {
		t.Error("a duplicate status through manual triage must be denied")
	}
}

// TestFindingsListsProgramFromStore simulates the state after a restart:
// a new server (empty in-memory registry), but the data is in the store. The program tab
// must still show from the store.
func TestFindingsListsProgramFromStore(t *testing.T) {
	st := store.NewMem()
	ctx := context.Background()
	f := &finding.Finding{
		Program: "demo", RunID: "r", Target: "https://demo.test",
		Type: "ssrf-via-fetch", Title: "SSRF", Severity: finding.SeverityHigh,
		Confidence: finding.ConfidenceMedium, Status: finding.StatusNew, SourceEngine: "nuclei",
		Location: finding.Location{URL: "https://demo.test/fetch"},
	}
	if _, err := st.Save(ctx, f); err != nil {
		t.Fatalf("seed Save: %v", err)
	}

	srv, err := NewServer(Config{ // empty in-memory registry
		Store:        st,
		Engines:      []engine.Engine{nuclei.Mock{}},
		AuthDisabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	rec := do(t, srv, "GET", "/findings", nil) // without ?program=
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /findings = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "ssrf-via-fetch") || !strings.Contains(body, ">demo<") {
		t.Errorf("a program from the store should show without a rescan:\n%s", body)
	}
}

func TestScanWithReconDiscovers(t *testing.T) {
	srv, st := newTestServer(t)
	rec := do(t, srv, "POST", "/scan", url.Values{
		"program":   {"demo"},
		"seeds":     {"demo.test"},
		"in_scope":  {"demo.test\n*.demo.test"},
		"out_scope": {"admin.demo.test"},
		"targets":   {""},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /scan = %d", rec.Code)
	}
	done := waitRunDone(t, srv, runIDFrom(t, rec.Body.String()))
	if !strings.Contains(done, "recon assets") {
		t.Error("the run status must show the recon asset count")
	}
	if !strings.Contains(done, "exfil.evil.test") {
		t.Error("an out-of-scope recon asset must show as denied")
	}
	if fs, _ := st.List(context.Background(), store.Query{Program: "demo"}); len(fs) == 0 {
		t.Error("there must be a finding from the in-scope recon asset")
	}
}

func TestReportFlow(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()

	rec0 := do(t, srv, "POST", "/scan", url.Values{
		"program": {"demo"}, "in_scope": {"demo.test"}, "targets": {"demo.test"},
	})
	waitRunDone(t, srv, runIDFrom(t, rec0.Body.String()))
	fs, _ := st.List(ctx, store.Query{Program: "demo"})
	if len(fs) == 0 {
		t.Fatal("no finding to report")
	}

	// Before anything is confirmed: the report is empty.
	rec := do(t, srv, "GET", "/report?program=demo", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "still empty") {
		t.Errorf("a report without confirmed findings must be an empty state (code=%d)", rec.Code)
	}

	// Confirm one finding.
	do(t, srv, "POST", "/findings/"+fs[0].ID+"/status", url.Values{"status": {"confirmed"}})

	rec = do(t, srv, "GET", "/report?program=demo", nil)
	body := rec.Body.String()
	if !strings.Contains(body, "DRAFT") || !strings.Contains(body, fs[0].Title) {
		t.Error("the report must hold the confirmed finding and be marked DRAFT")
	}

	// Download .md.
	rec = do(t, srv, "GET", "/report/download?program=demo", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Content-Disposition"), "report-demo.md") {
		t.Errorf("download .md failed: code=%d cd=%q", rec.Code, rec.Header().Get("Content-Disposition"))
	}
	if !strings.Contains(rec.Body.String(), "# Report") {
		t.Error("the .md content does not match")
	}

	// Print view (for Save as PDF).
	rec = do(t, srv, "GET", "/report/print?program=demo", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "window.print()") {
		t.Errorf("print view failed (code=%d)", rec.Code)
	}
}

func TestSettingsSecretFlow(t *testing.T) {
	srv, _ := newTestServer(t)

	rec := do(t, srv, "POST", "/settings/secrets", url.Values{
		"scope": {"global"}, "name": {"nuclei-key"}, "value": {"supersecret-xyz"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST add = %d, want 303", rec.Code)
	}

	rec = do(t, srv, "GET", "/settings?scope=global", nil)
	body := rec.Body.String()
	if !strings.Contains(body, "nuclei-key") {
		t.Error("the secret must be listed (name)")
	}
	if strings.Contains(body, "supersecret-xyz") {
		t.Error("the secret VALUE must not appear in the UI")
	}

	rec = do(t, srv, "POST", "/settings/secrets/delete", url.Values{
		"scope": {"global"}, "name": {"nuclei-key"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST delete = %d, want 303", rec.Code)
	}
	rec = do(t, srv, "GET", "/settings?scope=global", nil)
	if strings.Contains(rec.Body.String(), "nuclei-key") {
		t.Error("the secret must be gone after it is deleted")
	}
}

func TestAuditTrail(t *testing.T) {
	srv, _ := newTestServer(t)

	rec := do(t, srv, "POST", "/scan", url.Values{
		"program": {"demo"}, "in_scope": {"demo.test"}, "targets": {"demo.test\nevil.test"},
	})
	waitRunDone(t, srv, runIDFrom(t, rec.Body.String()))

	rec = do(t, srv, "GET", "/audit?program=demo", nil)
	body := rec.Body.String()
	if !strings.Contains(body, "integrity OK") {
		t.Error("the audit integrity must be OK")
	}
	if !strings.Contains(body, "scope.decision") {
		t.Error("the audit must hold the scope decision entries")
	}
	if !strings.Contains(body, "evil.test") {
		t.Error("the evil.test denial must be recorded in the audit")
	}
}
