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

// mkUser membuat satu akun di store (helper test RBAC).
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

// newAuthServer membuat server dengan login WAJIB dan satu admin bootstrap.
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

// postForm mengirim POST state-changing dengan CSRF (dan opsional session cookie).
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

	// GET /login → 200 + logo + form username/password (tanpa perlu kredensial).
	gr := httptest.NewRecorder()
	srv.ServeHTTP(gr, httptest.NewRequest("GET", "/login", nil))
	if gr.Code != http.StatusOK {
		t.Fatalf("GET /login = %d, ingin 200", gr.Code)
	}
	if b := gr.Body.String(); !strings.Contains(b, "Masuk") || !strings.Contains(b, "bughound-logo.png") || !strings.Contains(b, "Username") {
		t.Errorf("halaman login harus punya form username + logo:\n%s", b)
	}
	csrf := cookieValue(gr, csrfCookie)
	if csrf == "" {
		t.Fatal("csrf cookie tak diset di /login")
	}

	// Password salah → 401 + pesan.
	rec := postForm(srv, "/login", url.Values{"username": {"admin"}, "password": {"salah"}, "csrf": {csrf}}, csrf, "")
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "salah") {
		t.Fatalf("password salah = %d, ingin 401 + pesan:\n%s", rec.Code, rec.Body.String())
	}
	if cookieValue(rec, sessionCookie) != "" {
		t.Error("password salah tak boleh memberi sesi")
	}

	// Username tak dikenal → 401 (tak membocorkan bahwa user tak ada).
	un := postForm(srv, "/login", url.Values{"username": {"nobody"}, "password": {"s3kret"}, "csrf": {csrf}}, csrf, "")
	if un.Code != http.StatusUnauthorized {
		t.Fatalf("username tak dikenal = %d, ingin 401", un.Code)
	}

	// Kredensial benar → 303 /dashboard + session cookie.
	rec = postForm(srv, "/login", url.Values{"username": {"admin"}, "password": {"s3kret"}, "csrf": {csrf}}, csrf, "")
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/dashboard" {
		t.Fatalf("login benar = %d loc=%q, ingin 303 /dashboard", rec.Code, rec.Header().Get("Location"))
	}
	sess := cookieValue(rec, sessionCookie)
	if sess == "" {
		t.Fatal("session cookie tak diset setelah login")
	}

	// GET /scan dengan sesi → 200.
	req := httptest.NewRequest("GET", "/scan", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: sess})
	sr := httptest.NewRecorder()
	srv.ServeHTTP(sr, req)
	if sr.Code != http.StatusOK {
		t.Fatalf("GET /scan dengan sesi = %d, ingin 200", sr.Code)
	}

	// Logout → sesi batal; akses berikutnya dengan cookie lama di-redirect ke /login.
	lr := postForm(srv, "/logout", url.Values{"csrf": {csrf}}, csrf, sess)
	if lr.Code != http.StatusSeeOther || lr.Header().Get("Location") != "/login" {
		t.Fatalf("logout = %d loc=%q, ingin 303 /login", lr.Code, lr.Header().Get("Location"))
	}
	req2 := httptest.NewRequest("GET", "/scan", nil)
	req2.AddCookie(&http.Cookie{Name: sessionCookie, Value: sess})
	ar := httptest.NewRecorder()
	srv.ServeHTTP(ar, req2)
	if ar.Code != http.StatusFound || ar.Header().Get("Location") != "/login" {
		t.Fatalf("sesi setelah logout harus batal → /login, dapat %d loc=%q", ar.Code, ar.Header().Get("Location"))
	}
}

func TestLoginCSRFRequired(t *testing.T) {
	srv, _ := newAuthServer(t, "admin", "s3kret")
	// POST /login tanpa token CSRF → ditolak (403), meski kredensial benar.
	req := httptest.NewRequest("POST", "/login", strings.NewReader(url.Values{"username": {"admin"}, "password": {"s3kret"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("login tanpa CSRF = %d, ingin 403", rec.Code)
	}
}

func TestNoAuthSkipsLogin(t *testing.T) {
	// AuthDisabled: tak ada login; /login mengalihkan ke /dashboard, akses bebas.
	srv, _ := newTestServer(t)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/login", nil))
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/dashboard" {
		t.Fatalf("tanpa auth, /login harus → /dashboard, dapat %d loc=%q", rec.Code, rec.Header().Get("Location"))
	}
	// Halaman biasa tetap terbuka tanpa kredensial.
	sr := httptest.NewRecorder()
	srv.ServeHTTP(sr, httptest.NewRequest("GET", "/scan", nil))
	if sr.Code != http.StatusOK {
		t.Fatalf("tanpa auth, /scan harus 200, dapat %d", sr.Code)
	}
}
