package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"bughound/internal/finding"
	"bughound/internal/store"
)

// seedAPIFinding stores one finding (with evidence.request) and
// returns the id the store assigned — used to test the JSON API.
func seedAPIFinding(t *testing.T, st *store.Mem, program, locURL, request string, sev finding.Severity) string {
	t.Helper()
	res, err := st.Save(context.Background(), &finding.Finding{
		Program:      program,
		RunID:        "run1",
		Target:       "https://" + program + ".test",
		Type:         "sqli",
		Title:        "SQLi at " + locURL,
		Severity:     sev,
		Confidence:   finding.ConfidenceMedium,
		Status:       finding.StatusNew,
		SourceEngine: "nuclei-dast",
		Location:     finding.Location{URL: locURL, Method: "GET", Parameter: "q"},
		Evidence:     &finding.Evidence{Request: request},
	})
	if err != nil {
		t.Fatalf("seed Save: %v", err)
	}
	return res.ID
}

// TestAPIFindingsList: the findings of one program as JSON, including
// evidence.request, and it does not leak another program.
func TestAPIFindingsList(t *testing.T) {
	srv, st := newTestServer(t)
	id := seedAPIFinding(t, st, "acme", "https://acme.io/rest/products/search?q=x",
		"GET /rest/products/search?q=x' HTTP/1.1\r\nHost: acme.io\r\n\r\n", finding.SeverityCritical)
	seedAPIFinding(t, st, "acme", "https://acme.io/b", "GET /b HTTP/1.1\r\n\r\n", finding.SeverityLow)
	seedAPIFinding(t, st, "globex", "https://globex.io/c", "GET /c HTTP/1.1\r\n\r\n", finding.SeverityHigh)

	rec := do(t, srv, "GET", "/api/v1/findings?program=acme", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET list = %d, body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var resp apiFindingsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v — body=%s", err, rec.Body.String())
	}
	if resp.Count != 2 || len(resp.Findings) != 2 {
		t.Fatalf("count=%d findings=%d, want 2 (acme program only)", resp.Count, len(resp.Findings))
	}
	var sawRequest bool
	for _, f := range resp.Findings {
		if f.Program != "acme" {
			t.Errorf("another program's finding leaked: %s", f.Program)
		}
		if f.ID == id {
			if f.Evidence != nil && strings.Contains(f.Evidence.Request, "products/search") {
				sawRequest = true
			}
		}
	}
	if !sawRequest {
		t.Error("evidence.request is not carried in the list JSON (needed by the Burp extension)")
	}
}

// TestAPIFindingsProgramRequired: without ?program= → 400 JSON.
func TestAPIFindingsProgramRequired(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := do(t, srv, "GET", "/api/v1/findings", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("without program = %d, want 400", rec.Code)
	}
	var e apiError
	if json.Unmarshal(rec.Body.Bytes(), &e); e.Error == "" {
		t.Error("empty JSON error")
	}
}

// TestAPIFindingsInvalidFilter: an unknown status/severity is rejected (400), not
// silently ignored — consistent with default-deny.
func TestAPIFindingsInvalidFilter(t *testing.T) {
	srv, st := newTestServer(t)
	seedAPIFinding(t, st, "acme", "https://acme.io/a", "GET /a HTTP/1.1\r\n\r\n", finding.SeverityHigh)
	for _, qs := range []string{"program=acme&status=bogus", "program=acme&severity=whatever"} {
		rec := do(t, srv, "GET", "/api/v1/findings?"+qs, nil)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%q = %d, want 400", qs, rec.Code)
		}
	}
}

// TestAPIFindingsStatusFilter: a valid status filter really does filter.
func TestAPIFindingsStatusFilter(t *testing.T) {
	srv, st := newTestServer(t)
	seedAPIFinding(t, st, "acme", "https://acme.io/a", "GET /a HTTP/1.1\r\n\r\n", finding.SeverityHigh)
	seedAPIFinding(t, st, "acme", "https://acme.io/b", "GET /b HTTP/1.1\r\n\r\n", finding.SeverityLow)

	rec := do(t, srv, "GET", "/api/v1/findings?program=acme&status=confirmed", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("filter status = %d", rec.Code)
	}
	var resp apiFindingsResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Count != 0 {
		t.Errorf("status=confirmed = %d findings, want 0 (all still new)", resp.Count)
	}
}

// TestAPIFindingDetail: fetch one finding by id; an unknown id → 404.
func TestAPIFindingDetail(t *testing.T) {
	srv, st := newTestServer(t)
	id := seedAPIFinding(t, st, "acme", "https://acme.io/x?q=1",
		"GET /x?q=1' HTTP/1.1\r\nHost: acme.io\r\n\r\n", finding.SeverityCritical)

	rec := do(t, srv, "GET", "/api/v1/findings/"+id, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("detail = %d, body=%s", rec.Code, rec.Body.String())
	}
	var f finding.Finding
	if err := json.Unmarshal(rec.Body.Bytes(), &f); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if f.ID != id {
		t.Errorf("id = %q, want %q", f.ID, id)
	}
	if f.Evidence == nil || !strings.Contains(f.Evidence.Request, "/x?q=1") {
		t.Error("evidence.request missing from the detail")
	}

	rec404 := do(t, srv, "GET", "/api/v1/findings/does-not-exist", nil)
	if rec404.Code != http.StatusNotFound {
		t.Errorf("unknown id = %d, want 404", rec404.Code)
	}
}

// TestBurpPage: the Burp integration onboarding page renders with its core content,
// and the command example uses a real program from the store.
func TestBurpPage(t *testing.T) {
	srv, st := newTestServer(t)
	seedAPIFinding(t, st, "acme", "https://acme.io/a", "GET /a HTTP/1.1\r\n\r\n", finding.SeverityHigh)

	rec := do(t, srv, "GET", "/burp", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /burp = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"Burp Suite integration", "/api/v1/findings", "gradle shadowJar", "Community", "Send to Repeater"} {
		if !strings.Contains(body, want) {
			t.Errorf("the /burp page is missing %q", want)
		}
	}
	if !strings.Contains(body, "program=acme") {
		t.Error("the command example does not use a real program from the store")
	}
}

// TestAPIRequiresAuth proves the API endpoint is protected by the same front
// controller: without credentials → 401 JSON (NOT a 302 redirect to /login, which would
// confuse a machine client), and a valid HTTP Basic → 200. This is the path
// the Burp extension uses (the automation auth that already exists in the tool).
func TestAPIRequiresAuth(t *testing.T) {
	srv, st := newAuthServer(t, "admin", "s3kret-pass")
	seedAPIFinding(t, st, "acme", "https://acme.io/a", "GET /a HTTP/1.1\r\n\r\n", finding.SeverityHigh)
	const target = "/api/v1/findings?program=acme"

	// Without credentials → 401 JSON, no redirect.
	noauth := httptest.NewRecorder()
	srv.ServeHTTP(noauth, httptest.NewRequest("GET", target, nil))
	if noauth.Code != http.StatusUnauthorized {
		t.Fatalf("without auth = %d, want 401 (not a redirect %d)", noauth.Code, http.StatusFound)
	}
	if ct := noauth.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("auth error Content-Type = %q, want JSON", ct)
	}

	// HTTP Basic sah → 200.
	ok := httptest.NewRecorder()
	rok := httptest.NewRequest("GET", target, nil)
	rok.SetBasicAuth("admin", "s3kret-pass")
	srv.ServeHTTP(ok, rok)
	if ok.Code != http.StatusOK {
		t.Fatalf("Basic sah = %d, want 200, body=%s", ok.Code, ok.Body.String())
	}

	// Wrong Basic → 401.
	bad := httptest.NewRecorder()
	rbad := httptest.NewRequest("GET", target, nil)
	rbad.SetBasicAuth("admin", "wrong")
	srv.ServeHTTP(bad, rbad)
	if bad.Code != http.StatusUnauthorized {
		t.Errorf("wrong Basic = %d, want 401", bad.Code)
	}
}
