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

// newRBACServer: login REQUIRED with admin + operator + viewer ready to use.
func newRBACServer(t *testing.T) (*Server, *store.Mem) {
	t.Helper()
	srv, st := newAuthServer(t, "admin", "adminpw")
	mkUser(t, st, "oper", "operpw", auth.RoleOperator)
	mkUser(t, st, "view", "viewpw", auth.RoleViewer)
	return srv, st
}

// loginAs runs the real login flow and returns the csrf token + session.
func loginAs(t *testing.T, srv *Server, username, password string) (csrf, sess string) {
	t.Helper()
	gr := httptest.NewRecorder()
	srv.ServeHTTP(gr, httptest.NewRequest("GET", "/login", nil))
	csrf = cookieValue(gr, csrfCookie)
	if csrf == "" {
		t.Fatal("could not get the csrf from /login")
	}
	rec := postForm(srv, "/login", url.Values{"username": {username}, "password": {password}, "csrf": {csrf}}, csrf, "")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login %s failed: %d", username, rec.Code)
	}
	sess = cookieValue(rec, sessionCookie)
	if sess == "" {
		t.Fatalf("no session for %s", username)
	}
	return csrf, sess
}

// authedReq sends a request with a session (and csrf for state-changing).
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

	// Read allowed.
	if rec := authedReq(srv, "GET", "/findings", nil, csrf, sess); rec.Code != http.StatusOK {
		t.Fatalf("viewer GET /findings = %d, want 200", rec.Code)
	}
	// A write action is denied (403).
	if rec := authedReq(srv, "POST", "/scan", scanForm, csrf, sess); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer POST /scan = %d, want 403", rec.Code)
	}
	// The admin area is denied (403).
	if rec := authedReq(srv, "GET", "/users", nil, csrf, sess); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer GET /users = %d, want 403", rec.Code)
	}
}

func TestRBAC_OperatorCannotAdmin(t *testing.T) {
	srv, _ := newRBACServer(t)
	csrf, sess := loginAs(t, srv, "oper", "operpw")

	// An operator may run a scan (write) → partial 200.
	if rec := authedReq(srv, "POST", "/scan", scanForm, csrf, sess); rec.Code != http.StatusOK {
		t.Fatalf("operator POST /scan = %d, want 200", rec.Code)
	}
	// But must not reach the admin area.
	if rec := authedReq(srv, "GET", "/users", nil, csrf, sess); rec.Code != http.StatusForbidden {
		t.Fatalf("operator GET /users = %d, want 403", rec.Code)
	}
	if rec := authedReq(srv, "POST", "/users", url.Values{"username": {"x"}, "password": {"y"}, "role": {"viewer"}}, csrf, sess); rec.Code != http.StatusForbidden {
		t.Fatalf("operator POST /users = %d, want 403", rec.Code)
	}
}

func TestRBAC_AdminManagesUsers(t *testing.T) {
	srv, st := newRBACServer(t)
	csrf, sess := loginAs(t, srv, "admin", "adminpw")

	if rec := authedReq(srv, "GET", "/users", nil, csrf, sess); rec.Code != http.StatusOK {
		t.Fatalf("admin GET /users = %d, want 200", rec.Code)
	}
	// Create a new viewer.
	rec := authedReq(srv, "POST", "/users", url.Values{"username": {"newbie"}, "password": {"pw123456"}, "role": {"viewer"}}, csrf, sess)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("admin POST /users = %d, want 303:\n%s", rec.Code, rec.Body.String())
	}
	u, err := st.GetUser(context.Background(), "newbie")
	if err != nil || u.Role != "viewer" {
		t.Fatalf("the new user was not stored: %+v err=%v", u, err)
	}
	// The new user can log in and is read-only.
	c2, s2 := loginAs(t, srv, "newbie", "pw123456")
	if rec := authedReq(srv, "POST", "/scan", scanForm, c2, s2); rec.Code != http.StatusForbidden {
		t.Fatalf("new viewer POST /scan = %d, want 403", rec.Code)
	}
}

func TestRBAC_SelfAndLastAdminProtected(t *testing.T) {
	srv, _ := newRBACServer(t)
	csrf, sess := loginAs(t, srv, "admin", "adminpw")

	// Cannot delete its own account.
	rec := authedReq(srv, "POST", "/users/delete", url.Values{"username": {"admin"}}, csrf, sess)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "signed in") {
		t.Fatalf("delete self = %d, want 400 + message:\n%s", rec.Code, rec.Body.String())
	}
	// Deleting another user still works.
	if rec := authedReq(srv, "POST", "/users/delete", url.Values{"username": {"view"}}, csrf, sess); rec.Code != http.StatusSeeOther {
		t.Fatalf("delete viewer = %d, want 303", rec.Code)
	}
}
