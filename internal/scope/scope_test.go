package scope

import (
	"strings"
	"testing"
)

// mustGuard membangun Guard dan gagal bila ada entri yang tak terurai.
func mustGuard(t *testing.T, in, out []string) *Guard {
	t.Helper()
	g, errs := New(in, out)
	if len(errs) > 0 {
		t.Fatalf("New punya error tak terduga: %v", errs)
	}
	return g
}

// allow/deny helper assertion.
func wantAllow(t *testing.T, g *Guard, target string) {
	t.Helper()
	if r := g.Evaluate(target); !r.Allowed {
		t.Errorf("Evaluate(%q) = tolak (%s), ingin izin", target, r.Reason)
	}
}

func wantDeny(t *testing.T, g *Guard, target string, reason Reason) {
	t.Helper()
	r := g.Evaluate(target)
	if r.Allowed {
		t.Errorf("Evaluate(%q) = izin, ingin tolak", target)
		return
	}
	if reason != "" && r.Reason != reason {
		t.Errorf("Evaluate(%q) reason = %q, ingin %q", target, r.Reason, reason)
	}
}

func TestDefaultDeny(t *testing.T) {
	g := mustGuard(t, []string{"acme.io"}, nil)
	wantDeny(t, g, "unknown.com", ReasonNotInScope)
	wantAllow(t, g, "acme.io")
}

func TestHostExact_NotSubstring(t *testing.T) {
	g := mustGuard(t, []string{"acme.io"}, nil)
	wantAllow(t, g, "acme.io")
	wantDeny(t, g, "notacme.io", ReasonNotInScope)     // bukan substring
	wantDeny(t, g, "acme.io.evil.com", ReasonNotInScope) // suffix palsu
	wantDeny(t, g, "app.acme.io", ReasonNotInScope)      // host eksak != subdomain
}

func TestCaseAndTrailingDot(t *testing.T) {
	g := mustGuard(t, []string{"acme.io"}, nil)
	wantAllow(t, g, "ACME.io")
	wantAllow(t, g, "acme.io.")
	wantAllow(t, g, "AcMe.Io.")
}

func TestCredentialInURLStripped(t *testing.T) {
	g := mustGuard(t, []string{"acme.io"}, nil)
	wantAllow(t, g, "https://user:pass@acme.io/x")
	wantAllow(t, g, "user:pass@acme.io/x")
}

func TestWildcard(t *testing.T) {
	g := mustGuard(t, []string{"*.acme.io"}, nil)
	wantAllow(t, g, "app.acme.io")
	wantAllow(t, g, "a.b.acme.io")        // multi-level
	wantDeny(t, g, "acme.io", ReasonNotInScope) // apex tak tercakup wildcard
	wantDeny(t, g, "acme.io.evil.com", ReasonNotInScope)
	wantDeny(t, g, "notacme.io", ReasonNotInScope)
}

func TestWildcardPlusApex(t *testing.T) {
	g := mustGuard(t, []string{"*.acme.io", "acme.io"}, nil)
	wantAllow(t, g, "acme.io")     // apex didaftarkan terpisah
	wantAllow(t, g, "app.acme.io") // subdomain via wildcard
}

func TestOutOfScopeWins(t *testing.T) {
	g := mustGuard(t, []string{"*.acme.io"}, []string{"admin.acme.io"})
	wantAllow(t, g, "app.acme.io")
	r := g.Evaluate("admin.acme.io")
	if r.Allowed || r.Reason != ReasonOutOfScope {
		t.Errorf("admin.acme.io: %+v, ingin tolak out-of-scope", r)
	}
	if r.MatchedEntry != "admin.acme.io" {
		t.Errorf("MatchedEntry = %q, ingin admin.acme.io", r.MatchedEntry)
	}
}

func TestHomoglyphRejected(t *testing.T) {
	g := mustGuard(t, []string{"acme.io"}, nil)
	// 'а' di depan adalah Cyrillic U+0430, bukan Latin 'a'.
	wantDeny(t, g, "аcme.io", "") // ditolak (parse-error atau tidak cocok)
}

func TestMisleadingIPNotResolved(t *testing.T) {
	// Loopback eksplisit in-scope, tapi bentuk hex menyesatkan tak boleh lolos:
	// guard tidak pernah menafsirkannya sebagai 127.0.0.1.
	g := mustGuard(t, []string{"127.0.0.0/8"}, nil)
	wantAllow(t, g, "127.0.0.1")
	wantDeny(t, g, "0x7f.0.0.1", "")
	wantDeny(t, g, "2130706433", "") // 127.0.0.1 dalam desimal
}

func TestPrivateAndMetadataDeniedUnlessExplicit(t *testing.T) {
	// Hanya host wildcard di scope: IP privat/metadata harus ditolak.
	g := mustGuard(t, []string{"*.acme.io"}, nil)
	wantDeny(t, g, "169.254.169.254", ReasonNotInScope) // metadata cloud
	wantDeny(t, g, "10.1.2.3", ReasonNotInScope)
	wantDeny(t, g, "192.168.0.1", ReasonNotInScope)

	// Eksplisit in-scope lewat CIDR/IP => diizinkan.
	g2 := mustGuard(t, []string{"169.254.169.254", "10.0.0.0/8"}, nil)
	wantAllow(t, g2, "169.254.169.254")
	wantAllow(t, g2, "10.1.2.3")
	wantDeny(t, g2, "192.168.0.1", ReasonNotInScope)
}

func TestCIDRNumericMembership(t *testing.T) {
	g := mustGuard(t, []string{"203.0.113.0/24"}, []string{"203.0.113.5"})
	wantAllow(t, g, "203.0.113.10")
	wantAllow(t, g, "203.0.113.255")
	wantDeny(t, g, "203.0.114.1", ReasonNotInScope) // di luar rentang
	wantDeny(t, g, "203.0.113.5", ReasonOutOfScope)  // out-of-scope menang
}

func TestIPv6(t *testing.T) {
	g := mustGuard(t, []string{"2001:db8::/32"}, nil)
	wantAllow(t, g, "2001:db8::1")
	wantAllow(t, g, "[2001:db8::1]:8443")
	wantDeny(t, g, "2001:db9::1", ReasonNotInScope)
}

func TestPortPolicy(t *testing.T) {
	// Tanpa port eksplisit: semua port tercakup.
	g := mustGuard(t, []string{"acme.io"}, nil)
	wantAllow(t, g, "acme.io")
	wantAllow(t, g, "acme.io:8443")
	wantAllow(t, g, "https://acme.io:8443/x")

	// Dengan port eksplisit: hanya port itu.
	g2 := mustGuard(t, []string{"acme.io:443"}, nil)
	wantAllow(t, g2, "acme.io:443")
	wantDeny(t, g2, "acme.io:8443", ReasonNotInScope)
	wantDeny(t, g2, "acme.io", ReasonNotInScope) // tanpa port != port 443
}

func TestURLPrefixSegmentBoundary(t *testing.T) {
	g := mustGuard(t, []string{"https://acme.io/api/"}, nil)
	wantAllow(t, g, "https://acme.io/api")
	wantAllow(t, g, "https://acme.io/api/v1/users")
	wantAllow(t, g, "https://acme.io/api/../api/x") // path dinormalkan dulu
	wantDeny(t, g, "https://acme.io/apixyz", ReasonNotInScope)
	wantDeny(t, g, "https://acme.io/", ReasonNotInScope)
	wantDeny(t, g, "https://other.io/api", ReasonNotInScope)
}

func TestURLPrefixTraversalCannotEscape(t *testing.T) {
	g := mustGuard(t, []string{"https://acme.io/api/"}, nil)
	// ".." tak boleh keluar dari prefix untuk menyentuh /admin.
	wantDeny(t, g, "https://acme.io/api/../admin", ReasonNotInScope)
}

func TestFailClosedOnBadTarget(t *testing.T) {
	g := mustGuard(t, []string{"acme.io"}, nil)
	wantDeny(t, g, "", ReasonParseError)
	wantDeny(t, g, "   ", ReasonParseError)
	wantDeny(t, g, "http://", ReasonParseError)
}

func TestNewReportsUnparseableEntries(t *testing.T) {
	_, errs := New([]string{"a.*.io", "", "acme.io"}, []string{"***"})
	if len(errs) != 3 {
		t.Fatalf("ingin 3 error (a.*.io, entri kosong, ***), dapat %d: %v", len(errs), errs)
	}
}

func TestUnparseableOutOfScopeSurfaced(t *testing.T) {
	// Entri out-of-scope yang gagal urai WAJIB muncul sebagai error (under-block berbahaya).
	_, errs := New([]string{"acme.io"}, []string{"a.*.io"})
	if len(errs) == 0 {
		t.Fatal("entri out-of-scope tak terurai harus memunculkan error")
	}
	if !strings.Contains(errs[0].Error(), "out-of-scope") {
		t.Errorf("error harus menandai sisi out-of-scope: %v", errs[0])
	}
}

func TestResultTargetNormalized(t *testing.T) {
	g := mustGuard(t, []string{"acme.io"}, nil)
	r := g.Evaluate("https://user:pass@ACME.io.:443/a/../b")
	if r.Target != "acme.io:443/b" {
		t.Errorf("Target ternormalkan = %q, ingin acme.io:443/b", r.Target)
	}
}

func TestURLPrefixOnIPHost(t *testing.T) {
	g := mustGuard(t, []string{"http://203.0.113.10/app"}, nil)
	wantAllow(t, g, "http://203.0.113.10/app/x")
	wantDeny(t, g, "http://203.0.113.10/other", ReasonNotInScope)
	wantDeny(t, g, "http://203.0.113.11/app", ReasonNotInScope)
	wantDeny(t, g, "203.0.113.10", ReasonNotInScope) // path "/" bukan di bawah /app
}

// Port efektif dihitung dari skema; izin tetap butuh bukti bila tak diketahui.
func TestEffectivePortFromScheme(t *testing.T) {
	g := mustGuard(t, []string{"https://acme.io:443/"}, nil)
	wantAllow(t, g, "https://acme.io/x")
	wantAllow(t, g, "wss://acme.io/x")
	wantDeny(t, g, "http://acme.io/x", ReasonNotInScope)
	wantDeny(t, g, "ftp://acme.io/x", ReasonNotInScope)
	wantDeny(t, g, "acme.io", ReasonNotInScope)

	r := g.Evaluate("https://acme.io/x")
	if r.Target != "acme.io/x" {
		t.Errorf("Target = %q: port efektif tak boleh mengubah bentuk audit", r.Target)
	}
}

func TestPathScoped(t *testing.T) {
	g := mustGuard(t, []string{"*.acme.io", "acme.io", "203.0.113.0/24", "https://api.acme.io/v1"},
		[]string{"https://app.acme.io/admin", "shop.acme.io/cart", "https://port.acme.io:8443/x", "http://203.0.113.10/admin",
			"root.acme.io", "https://slash.acme.io/", "off.acme.io:8080", "*.dev.acme.io"})
	cases := map[string]bool{
		"app.acme.io:443":   true,  // eksklusi ber-path berskema
		"app.acme.io:8443":  true,  // entri tanpa port berlaku di semua port
		"APP.acme.io:443":   true,  // host dinormalkan
		"shop.acme.io:443":  true,  // bentuk tanpa skema, keluaran importer
		"port.acme.io:8443": true,  // port cocok
		"port.acme.io:443":  false, // eksklusi hanya untuk port lain
		"port.acme.io":      true,  // port tak diketahui: ragu berarti buka
		"203.0.113.10:443":  true,  // host IP
		"203.0.113.11:443":  false, // IP lain
		"acme.io:443":       false, // host lain, tak ada eksklusi ber-path
		"root.acme.io:443":  false, // eksklusi host tanpa path sudah cukup di CONNECT
		"slash.acme.io:443": false, // path akar setara seluruh host
		"off.acme.io:80":    false, // eksklusi berport tanpa path
		"x.dev.acme.io:443": false, // wildcard tak punya path
		"api.acme.io:443":   false, // entri in-scope ber-path bukan eksklusi
		"acme.io:notaport":  true,  // tak terurai: ragu berarti buka
		"":                  true,
	}
	for target, want := range cases {
		if got := g.PathScoped(target); got != want {
			t.Errorf("PathScoped(%q) = %v, ingin %v", target, got, want)
		}
	}
}

// Invarian penutup celah: URL yang ditolak guard tak boleh punya host:port yang
// lolos CONNECT tanpa dibuka, karena tunnel buta tak bisa menghadangnya.
func TestPathScopedCoversEveryDenial(t *testing.T) {
	ins := [][]string{{"acme.io"}, {"*.acme.io", "acme.io"}, {"203.0.113.10"}, {"203.0.113.0/24"}, {"https://acme.io/"}, {"acme.io:443"}}
	outs := [][]string{
		{"https://acme.io/admin"}, {"acme.io/admin"}, {"http://acme.io/admin"}, {"https://acme.io:443/admin"}, {"https://acme.io:8443/admin"},
		{"https://acme.io/admin/"}, {"https://acme.io/a/b/c"}, {"https://203.0.113.10/admin"}, {"http://203.0.113.10:8443/admin"},
	}
	authorities := []string{"acme.io:443", "acme.io:80", "acme.io:8443", "203.0.113.10:443", "203.0.113.10:8443"}
	paths := []string{"/", "/admin", "/admin/", "/admin/x", "/administrator", "/a/b/c", "/a/b/c/d", "/%61dmin", "/x/../admin"}
	checked := 0
	for _, in := range ins {
		for _, out := range outs {
			g := mustGuard(t, in, out)
			for _, a := range authorities {
				if !g.Evaluate(a).Allowed {
					continue // CONNECT sendiri sudah ditolak
				}
				for _, scheme := range []string{"http", "https"} {
					for _, p := range paths {
						u := scheme + "://" + a + p
						if r := g.Evaluate(u); !r.Allowed && r.Reason == ReasonOutOfScope {
							checked++
							if !g.PathScoped(a) {
								t.Errorf("in=%v out=%v: %s ditolak tapi %s tak dibuka", in, out, u, a)
							}
						}
					}
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("tak ada kombinasi teruji")
	}
}
