package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"bughound/internal/audit"
	"bughound/internal/auth"
	"bughound/internal/engine"
	"bughound/internal/engine/nuclei"
	"bughound/internal/secret"
	"bughound/internal/store"
)

// mkUser creates one account in the store (an RBAC test helper).
func mkUser(t *testing.T, us store.UserStore, username, password string, role auth.Role) {
	t.Helper()
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := us.CreateUser(context.Background(), store.User{Username: username, Role: string(role), PassHash: hash}); err != nil {
		t.Fatalf("CreateUser %s: %v", username, err)
	}
}

// newAuthServer builds a server with login REQUIRED and one bootstrap admin.
func newAuthServer(t *testing.T, adminUser, adminPass string) (*Server, *store.Mem) {
	t.Helper()
	st := store.NewMem()
	mkUser(t, st, adminUser, adminPass, auth.RoleAdmin)
	k, _ := secret.NewRandomKey()
	srv, err := NewServer(Config{
		Store:   st,
		Users:   st,
		Engines: []engine.Engine{nuclei.Mock{}},
		Vault:   secret.NewMemVault(secret.NewKeyring(k)),
		Audit:   audit.NewMemLog([]byte("k")),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv, st
}

// postForm sends a state-changing POST with CSRF (and an optional session cookie).
func postForm(srv *Server, path string, form url.Values, csrf, sess string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if csrf != "" {
		req.AddCookie(&http.Cookie{Name: csrfCookie, Value: csrf})
		req.Header.Set("X-CSRF-Token", csrf)
	}
	if sess != "" {
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: sess})
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func cookieValue(rec *httptest.ResponseRecorder, name string) string {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

func TestLoginSessionFlow(t *testing.T) {
	srv, _ := newAuthServer(t, "admin", "s3kret")

	// GET /login → 200 + logo + a username/password form (no credentials needed).
	gr := httptest.NewRecorder()
	srv.ServeHTTP(gr, httptest.NewRequest("GET", "/login", nil))
	if gr.Code != http.StatusOK {
		t.Fatalf("GET /login = %d, want 200", gr.Code)
	}
	if b := gr.Body.String(); !strings.Contains(b, "Sign in") || !strings.Contains(b, "bughound-logo.png") || !strings.Contains(b, "Username") {
		t.Errorf("the login page must have a username form + logo:\n%s", b)
	}
	csrf := cookieValue(gr, csrfCookie)
	if csrf == "" {
		t.Fatal("the csrf cookie is not set at /login")
	}

	// Wrong password → 401 + message.
	rec := postForm(srv, "/login", url.Values{"username": {"admin"}, "password": {"wrong"}, "csrf": {csrf}}, csrf, "")
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "Wrong") {
		t.Fatalf("wrong password = %d, want 401 + message:\n%s", rec.Code, rec.Body.String())
	}
	if cookieValue(rec, sessionCookie) != "" {
		t.Error("a wrong password must not grant a session")
	}

	// Unknown username → 401 (does not leak that the user does not exist).
	un := postForm(srv, "/login", url.Values{"username": {"nobody"}, "password": {"s3kret"}, "csrf": {csrf}}, csrf, "")
	if un.Code != http.StatusUnauthorized {
		t.Fatalf("unknown username = %d, want 401", un.Code)
	}

	// Correct credentials → 303 /dashboard + a session cookie.
	rec = postForm(srv, "/login", url.Values{"username": {"admin"}, "password": {"s3kret"}, "csrf": {csrf}}, csrf, "")
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/dashboard" {
		t.Fatalf("correct login = %d loc=%q, want 303 /dashboard", rec.Code, rec.Header().Get("Location"))
	}
	sess := cookieValue(rec, sessionCookie)
	if sess == "" {
		t.Fatal("the session cookie is not set after login")
	}

	// GET /scan with a session → 200.
	req := httptest.NewRequest("GET", "/scan", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: sess})
	sr := httptest.NewRecorder()
	srv.ServeHTTP(sr, req)
	if sr.Code != http.StatusOK {
		t.Fatalf("GET /scan with a session = %d, want 200", sr.Code)
	}

	// Logout → the session is void; the next access with the old cookie is redirected to /login.
	lr := postForm(srv, "/logout", url.Values{"csrf": {csrf}}, csrf, sess)
	if lr.Code != http.StatusSeeOther || lr.Header().Get("Location") != "/login" {
		t.Fatalf("logout = %d loc=%q, want 303 /login", lr.Code, lr.Header().Get("Location"))
	}
	req2 := httptest.NewRequest("GET", "/scan", nil)
	req2.AddCookie(&http.Cookie{Name: sessionCookie, Value: sess})
	ar := httptest.NewRecorder()
	srv.ServeHTTP(ar, req2)
	if ar.Code != http.StatusFound || ar.Header().Get("Location") != "/login" {
		t.Fatalf("the session after logout must be void → /login, got %d loc=%q", ar.Code, ar.Header().Get("Location"))
	}
}

func TestLoginCSRFRequired(t *testing.T) {
	srv, _ := newAuthServer(t, "admin", "s3kret")
	// POST /login without a CSRF token → rejected (403), even with correct credentials.
	req := httptest.NewRequest("POST", "/login", strings.NewReader(url.Values{"username": {"admin"}, "password": {"s3kret"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("login without CSRF = %d, want 403", rec.Code)
	}
}

func TestNoAuthSkipsLogin(t *testing.T) {
	// AuthDisabled: no login; /login redirects to /dashboard, access is open.
	srv, _ := newTestServer(t)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/login", nil))
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/dashboard" {
		t.Fatalf("without auth, /login must → /dashboard, got %d loc=%q", rec.Code, rec.Header().Get("Location"))
	}
	// An ordinary page stays open without credentials.
	sr := httptest.NewRecorder()
	srv.ServeHTTP(sr, httptest.NewRequest("GET", "/scan", nil))
	if sr.Code != http.StatusOK {
		t.Fatalf("without auth, /scan must be 200, got %d", sr.Code)
	}
}
