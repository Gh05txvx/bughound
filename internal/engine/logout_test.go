package engine

import "testing"

func TestIsLogoutURL(t *testing.T) {
	for _, s := range []string{
		"https://app.test/logout", "http://app.test:8080/LogOut", "https://app.test/api/auth/signout",
		"https://app.test/users/sign_out", "https://app.test/user/log-out?next=/", "https://app.test/LogOff.aspx",
		"https://app.test/wp-login.php?action=logout", "https://app.test/web/session/logout",
	} {
		if !IsLogoutURL(s) {
			t.Errorf("%q must be detected as logout", s)
		}
	}
	for _, s := range []string{
		"https://app.test/", "https://app.test/login", "https://app.test/logo.png", "https://app.test/signup",
		"https://app.test/blog/outline", "https://app.test/catalog",
		// the host is not matched: an authenticated scan must not drop this whole host
		"https://catalogoutlet.test/", "https://signoff.corp.test/app", "signoff.corp.test", "logout.test:8443",
	} {
		if IsLogoutURL(s) {
			t.Errorf("%q is NOT a logout route (an authenticated scan must not skip it)", s)
		}
	}
}

func TestIsLogoutPath(t *testing.T) {
	for _, s := range []string{"logout", "/logout", "api/auth/sign-out", "/LogOff.aspx", "signoff"} {
		if !IsLogoutPath(s) {
			t.Errorf("%q must be detected as a logout path", s)
		}
	}
	for _, s := range []string{"login", "/logo.png", "signup", "/blog/outline", "admin"} {
		if IsLogoutPath(s) {
			t.Errorf("%q is NOT a logout path", s)
		}
	}
}
