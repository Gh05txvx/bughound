package engine

import "testing"

func TestIsLogoutURL(t *testing.T) {
	for _, s := range []string{
		"https://app.test/logout", "http://app.test:8080/LogOut", "https://app.test/api/auth/signout",
		"https://app.test/users/sign_out", "https://app.test/user/log-out?next=/", "https://app.test/LogOff.aspx",
		"https://app.test/wp-login.php?action=logout", "https://app.test/web/session/logout",
	} {
		if !IsLogoutURL(s) {
			t.Errorf("%q harus terdeteksi sebagai logout", s)
		}
	}
	for _, s := range []string{
		"https://app.test/", "https://app.test/login", "https://app.test/logo.png", "https://app.test/signup",
		"https://app.test/blog/outline", "https://app.test/catalog",
		// host tak ikut dicocokkan: scan berlogin tak boleh membuang seluruh host ini
		"https://catalogoutlet.test/", "https://signoff.corp.test/app", "signoff.corp.test", "logout.test:8443",
	} {
		if IsLogoutURL(s) {
			t.Errorf("%q BUKAN route logout (scan berlogin tak boleh melewatkannya)", s)
		}
	}
}

func TestIsLogoutPath(t *testing.T) {
	for _, s := range []string{"logout", "/logout", "api/auth/sign-out", "/LogOff.aspx", "signoff"} {
		if !IsLogoutPath(s) {
			t.Errorf("%q harus terdeteksi sebagai path logout", s)
		}
	}
	for _, s := range []string{"login", "/logo.png", "signup", "/blog/outline", "admin"} {
		if IsLogoutPath(s) {
			t.Errorf("%q BUKAN path logout", s)
		}
	}
}
