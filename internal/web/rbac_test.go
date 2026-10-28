package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"bughound/internal/auth"
	"bughound/internal/store"
)

// newRBACServer: login WAJIB dengan admin + operator + viewer siap pakai.
func newRBACServer(t *testing.T) (*Server, *store.Mem) {
	t.Helper()
	srv, st := newAuthServer(t, "admin", "adminpw")
	mkUser(t, st, "oper", "operpw", auth.RoleOperator)
	mkUser(t, st, "view", "viewpw", auth.RoleViewer)
	return srv, st
}

// loginAs menjalankan alur login nyata dan mengembalikan token csrf + sesi.
func loginAs(t *testing.T, srv *Server, username, password string) (csrf, sess string) {
	t.Helper()
	gr := httptest.NewRecorder()
	srv.ServeHTTP(gr, httptest.NewRequest("GET", "/login", nil))
	csrf = cookieValue(gr, csrfCookie)
	if csrf == "" {
		t.Fatal("tak dapat csrf dari /login")
	}
	rec := postForm(srv, "/login", url.Values{"username": {username}, "password": {password}, "csrf": {csrf}}, csrf, "")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login %s gagal: %d", username, rec.Code)
	}
	sess = cookieValue(rec, sessionCookie)
	if sess == "" {
		t.Fatalf("tak ada sesi untuk %s", username)
	}
	return csrf, sess
}

// authedReq mengirim permintaan dengan sesi (dan csrf untuk state-changing).
func authedReq(srv *Server, method, target string, form url.Values, csrf, sess string) *httptest.ResponseRecorder {
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
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: sess})
	req.AddCookie(&http.Cookie{Name: csrfCookie, Value: csrf})
	if method != http.MethodGet {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

var scanForm = url.Values{"program": {"demo"}, "in_scope": {"demo.test"}, "targets": {"demo.test"}}

func TestRBAC_ViewerReadOnly(t *testing.T) {
	srv, _ := newRBACServer(t)
	csrf, sess := loginAs(t, srv, "view", "viewpw")

	// Baca diizinkan.
	if rec := authedReq(srv, "GET", "/findings", nil, csrf, sess); rec.Code != http.StatusOK {
		t.Fatalf("viewer GET /findings = %d, ingin 200", rec.Code)
	}
	// Aksi tulis ditolak (403).
	if rec := authedReq(srv, "POST", "/scan", scanForm, csrf, sess); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer POST /scan = %d, ingin 403", rec.Code)
	}
	// Area admin ditolak (403).
	if rec := authedReq(srv, "GET", "/users", nil, csrf, sess); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer GET /users = %d, ingin 403", rec.Code)
	}
}

func TestRBAC_OperatorCannotAdmin(t *testing.T) {
	srv, _ := newRBACServer(t)
	csrf, sess := loginAs(t, srv, "oper", "operpw")

	// Operator boleh menjalankan scan (tulis) → partial 200.
	if rec := authedReq(srv, "POST", "/scan", scanForm, csrf, sess); rec.Code != http.StatusOK {
		t.Fatalf("operator POST /scan = %d, ingin 200", rec.Code)
	}
	// Tapi tak boleh ke area admin.
	if rec := authedReq(srv, "GET", "/users", nil, csrf, sess); rec.Code != http.StatusForbidden {
		t.Fatalf("operator GET /users = %d, ingin 403", rec.Code)
	}
	if rec := authedReq(srv, "POST", "/users", url.Values{"username": {"x"}, "password": {"y"}, "role": {"viewer"}}, csrf, sess); rec.Code != http.StatusForbidden {
		t.Fatalf("operator POST /users = %d, ingin 403", rec.Code)
	}
}

func TestRBAC_AdminManagesUsers(t *testing.T) {
	srv, st := newRBACServer(t)
	csrf, sess := loginAs(t, srv, "admin", "adminpw")

	if rec := authedReq(srv, "GET", "/users", nil, csrf, sess); rec.Code != http.StatusOK {
		t.Fatalf("admin GET /users = %d, ingin 200", rec.Code)
	}
	// Buat viewer baru.
	rec := authedReq(srv, "POST", "/users", url.Values{"username": {"newbie"}, "password": {"pw123456"}, "role": {"viewer"}}, csrf, sess)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("admin POST /users = %d, ingin 303:\n%s", rec.Code, rec.Body.String())
	}
	u, err := st.GetUser(context.Background(), "newbie")
	if err != nil || u.Role != "viewer" {
		t.Fatalf("user baru tak tersimpan: %+v err=%v", u, err)
	}
	// User baru bisa login dan read-only.
	c2, s2 := loginAs(t, srv, "newbie", "pw123456")
	if rec := authedReq(srv, "POST", "/scan", scanForm, c2, s2); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer baru POST /scan = %d, ingin 403", rec.Code)
	}
}

func TestRBAC_SelfAndLastAdminProtected(t *testing.T) {
	srv, _ := newRBACServer(t)
	csrf, sess := loginAs(t, srv, "admin", "adminpw")

	// Tak bisa menghapus akun sendiri.
	rec := authedReq(srv, "POST", "/users/delete", url.Values{"username": {"admin"}}, csrf, sess)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "sedang login") {
		t.Fatalf("hapus diri = %d, ingin 400 + pesan:\n%s", rec.Code, rec.Body.String())
	}
	// Menghapus pengguna lain tetap bisa.
	if rec := authedReq(srv, "POST", "/users/delete", url.Values{"username": {"view"}}, csrf, sess); rec.Code != http.StatusSeeOther {
		t.Fatalf("hapus viewer = %d, ingin 303", rec.Code)
	}
}
