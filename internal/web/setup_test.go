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

// newSetupServer builds a login-required server with an EMPTY user store, so the
// first-run /setup gate is active.
func newSetupServer(t *testing.T) (*Server, *store.Mem) {
	t.Helper()
	st := store.NewMem()
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

func TestFirstRunSetupFlow(t *testing.T) {
	srv, st := newSetupServer(t)
	ctx := context.Background()

	// With no account, every page funnels to /setup.
	dr := httptest.NewRecorder()
	srv.ServeHTTP(dr, httptest.NewRequest("GET", "/dashboard", nil))
	if dr.Code != http.StatusFound || dr.Header().Get("Location") != "/setup" {
		t.Fatalf("GET /dashboard with no account = %d loc=%q, want 302 /setup", dr.Code, dr.Header().Get("Location"))
	}

	// GET /setup → 200 + form; grab the CSRF cookie.
	gr := httptest.NewRecorder()
	srv.ServeHTTP(gr, httptest.NewRequest("GET", "/setup", nil))
	if gr.Code != http.StatusOK || !strings.Contains(gr.Body.String(), "Create admin") {
		t.Fatalf("GET /setup = %d, want 200 + form:\n%s", gr.Code, gr.Body.String())
	}
	csrf := cookieValue(gr, csrfCookie)
	if csrf == "" {
		t.Fatal("the csrf cookie is not set at /setup")
	}

	// Mismatched passwords → 400, no account created.
	mm := postForm(srv, "/setup", url.Values{"username": {"root"}, "password": {"longenough1"}, "confirm": {"different1"}, "csrf": {csrf}}, csrf, "")
	if mm.Code != http.StatusBadRequest || !strings.Contains(mm.Body.String(), "do not match") {
		t.Fatalf("mismatched passwords = %d, want 400 + message:\n%s", mm.Code, mm.Body.String())
	}
	if n, _ := st.CountUsers(ctx); n != 0 {
		t.Fatalf("a failed setup must not create an account; got %d users", n)
	}

	// Too-short password → 400.
	if sh := postForm(srv, "/setup", url.Values{"username": {"root"}, "password": {"short"}, "confirm": {"short"}, "csrf": {csrf}}, csrf, ""); sh.Code != http.StatusBadRequest {
		t.Fatalf("short password = %d, want 400", sh.Code)
	}

	// Valid setup → 303 /dashboard + a session; the account is the admin.
	ok := postForm(srv, "/setup", url.Values{"username": {"root"}, "password": {"longenough1"}, "confirm": {"longenough1"}, "csrf": {csrf}}, csrf, "")
	if ok.Code != http.StatusSeeOther || ok.Header().Get("Location") != "/dashboard" {
		t.Fatalf("valid setup = %d loc=%q, want 303 /dashboard", ok.Code, ok.Header().Get("Location"))
	}
	sess := cookieValue(ok, sessionCookie)
	if sess == "" {
		t.Fatal("setup must grant a session")
	}
	if u, err := st.GetUser(ctx, "root"); err != nil || u.Role != string(auth.RoleAdmin) {
		t.Fatalf("the first account must be the admin; got %+v err=%v", u, err)
	}

	// Setup is now closed: GET /setup → /login, and a second POST makes no account.
	cr := httptest.NewRecorder()
	srv.ServeHTTP(cr, httptest.NewRequest("GET", "/setup", nil))
	if cr.Code != http.StatusFound || cr.Header().Get("Location") != "/login" {
		t.Fatalf("GET /setup after setup = %d loc=%q, want 302 /login", cr.Code, cr.Header().Get("Location"))
	}
	again := postForm(srv, "/setup", url.Values{"username": {"root2"}, "password": {"longenough1"}, "confirm": {"longenough1"}, "csrf": {csrf}}, csrf, "")
	if again.Header().Get("Location") != "/login" {
		t.Fatalf("a second setup must be closed → /login, got %d loc=%q", again.Code, again.Header().Get("Location"))
	}
	if n, _ := st.CountUsers(ctx); n != 1 {
		t.Fatalf("setup must create exactly one account; got %d", n)
	}

	// The granted session works like a normal admin login.
	req := httptest.NewRequest("GET", "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: sess})
	sr := httptest.NewRecorder()
	srv.ServeHTTP(sr, req)
	if sr.Code != http.StatusOK {
		t.Fatalf("GET /dashboard with the setup session = %d, want 200", sr.Code)
	}
}
