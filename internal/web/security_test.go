package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"bughound/internal/store"
)

// Audit test (BH-P03-APPSEC): a stored secret value must
// never appear on any endpoint (findings, report, audit, settings, scan).
func TestAudit_SecretNeverLeaksAcrossEndpoints(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()
	const canary = "LEAK-CANARY-9z8y7x"

	// Store a secret through Settings.
	if rec := do(t, srv, "POST", "/settings/secrets", url.Values{
		"scope": {"global"}, "name": {"engine-token"}, "value": {canary},
	}); rec.Code != 303 {
		t.Fatalf("save secret = %d", rec.Code)
	}

	// Run a scan + confirm + report (the paths most likely to leak).
	rec := do(t, srv, "POST", "/scan", url.Values{
		"program": {"demo"}, "in_scope": {"demo.test"}, "targets": {"demo.test"},
	})
	waitRunDone(t, srv, runIDFrom(t, rec.Body.String()))
	fs, _ := st.List(ctx, store.Query{Program: "demo"})
	if len(fs) > 0 {
		do(t, srv, "POST", "/findings/"+fs[0].ID+"/status", url.Values{"status": {"confirmed"}})
	}

	endpoints := []string{
		"/settings?scope=global",
		"/findings?program=demo",
		"/report?program=demo",
		"/report/download?program=demo",
		"/report/print?program=demo",
		"/audit?program=demo",
		"/scan",
	}
	for _, ep := range endpoints {
		body := do(t, srv, "GET", ep, nil).Body.String()
		if strings.Contains(body, canary) {
			t.Errorf("LEAK: the secret value appears at %s", ep)
		}
	}
}

// The audit trail must stay intact (Verify OK) after many operations.
func TestAudit_TrailIntegrityAfterManyOps(t *testing.T) {
	srv, _ := newTestServer(t)
	for i := 0; i < 3; i++ {
		rec := do(t, srv, "POST", "/scan", url.Values{
			"program": {"demo"}, "in_scope": {"demo.test"}, "out_scope": {"admin.demo.test"},
			"targets": {"demo.test\nevil.test\nadmin.demo.test"},
		})
		waitRunDone(t, srv, runIDFrom(t, rec.Body.String()))
	}
	body := do(t, srv, "GET", "/audit?program=demo", nil).Body.String()
	if !strings.Contains(body, "integrity OK") {
		t.Error("the audit trail must stay verified intact after many runs")
	}
	if strings.Contains(body, "INTEGRITY BROKEN") {
		t.Error("the audit trail must not be broken")
	}
}

// BH-F01 remediation: a POST without a CSRF token / cross-site must be denied.
func TestAudit_CSRFBlocksForgedPost(t *testing.T) {
	srv, _ := newTestServer(t)
	form := url.Values{"program": {"x"}, "in_scope": {"demo.test"}, "targets": {"demo.test"}}

	// Without a cookie & token -> 403.
	req := httptest.NewRequest("POST", "/scan", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST without CSRF must be 403, got %d", rec.Code)
	}

	// Valid token but Sec-Fetch-Site: cross-site -> still 403.
	gr := httptest.NewRecorder()
	srv.ServeHTTP(gr, httptest.NewRequest("GET", "/scan", nil))
	var tok string
	for _, c := range gr.Result().Cookies() {
		if c.Name == csrfCookie {
			tok = c.Value
		}
	}
	req2 := httptest.NewRequest("POST", "/scan", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.AddCookie(&http.Cookie{Name: csrfCookie, Value: tok})
	req2.Header.Set("X-CSRF-Token", tok)
	req2.Header.Set("Sec-Fetch-Site", "cross-site")
	rec2 := httptest.NewRecorder()
	srv.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("a cross-site POST must be 403, got %d", rec2.Code)
	}
}

// Regression: a VALID non-HTMX form POST using the token in a field + `Origin: null`
// (sent by Chromium for a same-origin form navigation under Referrer-Policy:
// no-referrer) must be ACCEPTED. Before the fix, Origin "null" was treated as a
// mismatch and rejected every non-HTMX form. The defense stays: the token is required &
// cross-site is still denied.
func TestAudit_CSRFFormFieldNullOriginAccepted(t *testing.T) {
	srv, st := newTestServer(t)

	// Take the token cookie from the GET.
	gr := httptest.NewRecorder()
	srv.ServeHTTP(gr, httptest.NewRequest("GET", "/programs/edit", nil))
	var tok string
	for _, c := range gr.Result().Cookies() {
		if c.Name == csrfCookie {
			tok = c.Value
		}
	}
	if tok == "" {
		t.Fatal("could not get the CSRF token from the GET")
	}
	form := url.Values{"name": {"csrfnull"}, "in_scope": {"demo.test"}}

	// Token in a body FIELD (not the header) + Origin: null + same-origin -> 303.
	req := httptest.NewRequest("POST", "/programs", strings.NewReader(addField(form, "csrf", tok).Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookie, Value: tok})
	req.Header.Set("Origin", "null")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("a valid form POST (Origin: null) must be 303, got %d", rec.Code)
	}
	if _, err := st.GetProgram(context.Background(), "csrfnull"); err != nil {
		t.Fatalf("the program must be stored after the POST is accepted: %v", err)
	}

	// A WRONG token + Origin: null -> still 403 (the token stays required).
	bad := httptest.NewRequest("POST", "/programs", strings.NewReader(addField(form, "csrf", "wrong").Encode()))
	bad.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	bad.AddCookie(&http.Cookie{Name: csrfCookie, Value: tok})
	bad.Header.Set("Origin", "null")
	badRec := httptest.NewRecorder()
	srv.ServeHTTP(badRec, bad)
	if badRec.Code != http.StatusForbidden {
		t.Fatalf("a wrong token (Origin: null) must still be 403, got %d", badRec.Code)
	}

	// Origin: null + Sec-Fetch-Site: cross-site -> still 403 (cross-site denied).
	xs := httptest.NewRequest("POST", "/programs", strings.NewReader(addField(form, "csrf", tok).Encode()))
	xs.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	xs.AddCookie(&http.Cookie{Name: csrfCookie, Value: tok})
	xs.Header.Set("Origin", "null")
	xs.Header.Set("Sec-Fetch-Site", "cross-site")
	xsRec := httptest.NewRecorder()
	srv.ServeHTTP(xsRec, xs)
	if xsRec.Code != http.StatusForbidden {
		t.Fatalf("cross-site (Origin: null) must be 403, got %d", xsRec.Code)
	}
}

// addField returns a copy of v with one extra field.
func addField(v url.Values, k, val string) url.Values {
	out := url.Values{}
	for kk, vv := range v {
		out[kk] = append([]string(nil), vv...)
	}
	out.Set(k, val)
	return out
}

// BH-F01 remediation: HTTP Basic auth (automation/CLI) against the UserStore.
func TestAudit_BasicAuthEnforced(t *testing.T) {
	srv, _ := newAuthServer(t, "ops", "s3kret")

	// Without credentials (browser) -> redirect to the session login page.
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/scan", nil))
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/login" {
		t.Fatalf("without auth must redirect to /login, got %d (loc=%q)", rec.Code, rec.Header().Get("Location"))
	}
	// Correct username + password -> 200.
	req := httptest.NewRequest("GET", "/scan", nil)
	req.SetBasicAuth("ops", "s3kret")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("correct auth must be 200, got %d", rec.Code)
	}
	// Wrong password -> 401.
	req = httptest.NewRequest("GET", "/scan", nil)
	req.SetBasicAuth("ops", "wrong")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a wrong password must be 401, got %d", rec.Code)
	}
	// Unknown username -> 401.
	req = httptest.NewRequest("GET", "/scan", nil)
	req.SetBasicAuth("ghost", "s3kret")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("an unknown username must be 401, got %d", rec.Code)
	}
}
