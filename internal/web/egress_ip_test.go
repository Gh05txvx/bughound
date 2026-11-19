package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// echoIPServer replies with a fixed IP as plain text, like ipify. The handler's
// throwaway guard allows its (loopback) host because it is the sole in-scope entry.
func echoIPServer(t *testing.T, ip string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(ip + "\n"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func adminLogin(t *testing.T, srv *Server, user, pass string) (csrf, sess string) {
	t.Helper()
	gr := httptest.NewRecorder()
	srv.ServeHTTP(gr, httptest.NewRequest("GET", "/login", nil))
	csrf = cookieValue(gr, csrfCookie)
	lr := postForm(srv, "/login", url.Values{"username": {user}, "password": {pass}, "csrf": {csrf}}, csrf, "")
	sess = cookieValue(lr, sessionCookie)
	if sess == "" {
		t.Fatalf("no session for %s", user)
	}
	return csrf, sess
}

// Admin: the /proxy card shows, and POST /proxy/myip returns the device IP the echo reports.
func TestEgressIPCheckAdmin(t *testing.T) {
	srv, _ := newAuthServer(t, "admin", "s3kret")
	echo := echoIPServer(t, "203.0.113.7")
	csrf, sess := adminLogin(t, srv, "admin", "s3kret")

	pr := httptest.NewRequest("GET", "/proxy", nil)
	pr.AddCookie(&http.Cookie{Name: sessionCookie, Value: sess})
	prec := httptest.NewRecorder()
	srv.ServeHTTP(prec, pr)
	if !strings.Contains(prec.Body.String(), "My egress IP") {
		t.Errorf("admin /proxy must show the My egress IP card:\n%s", prec.Body.String())
	}

	res := postForm(srv, "/proxy/myip", url.Values{"endpoint": {echo.URL}, "csrf": {csrf}}, csrf, sess)
	if res.Code != http.StatusOK {
		t.Fatalf("POST /proxy/myip = %d, want 200:\n%s", res.Code, res.Body.String())
	}
	if b := res.Body.String(); !strings.Contains(b, "203.0.113.7") || !strings.Contains(b, "Device IP") {
		t.Errorf("the result must show the device IP from the echo:\n%s", b)
	}
}

// Viewer: the control-plane check is admin-only (403) and the card is hidden.
func TestEgressIPCheckNonAdminForbidden(t *testing.T) {
	srv, us := newAuthServer(t, "admin", "s3kret")
	mkUser(t, us, "viewer1", "viewpass1", "viewer")
	csrf, sess := adminLogin(t, srv, "viewer1", "viewpass1")

	res := postForm(srv, "/proxy/myip", url.Values{"endpoint": {"https://api.ipify.org"}, "csrf": {csrf}}, csrf, sess)
	if res.Code != http.StatusForbidden {
		t.Fatalf("viewer POST /proxy/myip = %d, want 403", res.Code)
	}

	pr := httptest.NewRequest("GET", "/proxy", nil)
	pr.AddCookie(&http.Cookie{Name: sessionCookie, Value: sess})
	prec := httptest.NewRecorder()
	srv.ServeHTTP(prec, pr)
	if strings.Contains(prec.Body.String(), "My egress IP") {
		t.Error("the My egress IP card must be hidden for a viewer")
	}
}
