package scope

import (
	"strings"
	"testing"
)

// mustGuard builds a Guard and fails if any entry does not parse.
func mustGuard(t *testing.T, in, out []string) *Guard {
	t.Helper()
	g, errs := New(in, out)
	if len(errs) > 0 {
		t.Fatalf("New has an unexpected error: %v", errs)
	}
	return g
}

// allow/deny helper assertion.
func wantAllow(t *testing.T, g *Guard, target string) {
	t.Helper()
	if r := g.Evaluate(target); !r.Allowed {
		t.Errorf("Evaluate(%q) = deny (%s), want allow", target, r.Reason)
	}
}

func wantDeny(t *testing.T, g *Guard, target string, reason Reason) {
	t.Helper()
	r := g.Evaluate(target)
	if r.Allowed {
		t.Errorf("Evaluate(%q) = allow, want deny", target)
		return
	}
	if reason != "" && r.Reason != reason {
		t.Errorf("Evaluate(%q) reason = %q, want %q", target, r.Reason, reason)
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
	wantDeny(t, g, "notacme.io", ReasonNotInScope)     // not a substring
	wantDeny(t, g, "acme.io.evil.com", ReasonNotInScope) // fake suffix
	wantDeny(t, g, "app.acme.io", ReasonNotInScope)      // exact host != subdomain
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
	wantDeny(t, g, "acme.io", ReasonNotInScope) // apex not covered by the wildcard
	wantDeny(t, g, "acme.io.evil.com", ReasonNotInScope)
	wantDeny(t, g, "notacme.io", ReasonNotInScope)
}

func TestWildcardPlusApex(t *testing.T) {
	g := mustGuard(t, []string{"*.acme.io", "acme.io"}, nil)
	wantAllow(t, g, "acme.io")     // the apex is listed separately
	wantAllow(t, g, "app.acme.io") // subdomain via wildcard
}

func TestOutOfScopeWins(t *testing.T) {
	g := mustGuard(t, []string{"*.acme.io"}, []string{"admin.acme.io"})
	wantAllow(t, g, "app.acme.io")
	r := g.Evaluate("admin.acme.io")
	if r.Allowed || r.Reason != ReasonOutOfScope {
		t.Errorf("admin.acme.io: %+v, want out-of-scope deny", r)
	}
	if r.MatchedEntry != "admin.acme.io" {
		t.Errorf("MatchedEntry = %q, want admin.acme.io", r.MatchedEntry)
	}
}

func TestHomoglyphRejected(t *testing.T) {
	g := mustGuard(t, []string{"acme.io"}, nil)
	// the leading 'а' is Cyrillic U+0430, not Latin 'a'.
	wantDeny(t, g, "аcme.io", "") // denied (parse-error or no match)
}

func TestMisleadingIPNotResolved(t *testing.T) {
	// Loopback is explicitly in-scope, but a misleading hex form must not pass:
	// the guard never reads it as 127.0.0.1.
	g := mustGuard(t, []string{"127.0.0.0/8"}, nil)
	wantAllow(t, g, "127.0.0.1")
	wantDeny(t, g, "0x7f.0.0.1", "")
	wantDeny(t, g, "2130706433", "") // 127.0.0.1 in decimal
}

func TestPrivateAndMetadataDeniedUnlessExplicit(t *testing.T) {
	// Only a wildcard host in scope: private/metadata IPs must be denied.
	g := mustGuard(t, []string{"*.acme.io"}, nil)
	wantDeny(t, g, "169.254.169.254", ReasonNotInScope) // metadata cloud
	wantDeny(t, g, "10.1.2.3", ReasonNotInScope)
	wantDeny(t, g, "192.168.0.1", ReasonNotInScope)

	// Explicitly in-scope through CIDR/IP => allowed.
	g2 := mustGuard(t, []string{"169.254.169.254", "10.0.0.0/8"}, nil)
	wantAllow(t, g2, "169.254.169.254")
	wantAllow(t, g2, "10.1.2.3")
	wantDeny(t, g2, "192.168.0.1", ReasonNotInScope)
}

func TestCIDRNumericMembership(t *testing.T) {
	g := mustGuard(t, []string{"203.0.113.0/24"}, []string{"203.0.113.5"})
	wantAllow(t, g, "203.0.113.10")
	wantAllow(t, g, "203.0.113.255")
	wantDeny(t, g, "203.0.114.1", ReasonNotInScope) // outside the range
	wantDeny(t, g, "203.0.113.5", ReasonOutOfScope)  // out-of-scope wins
}

func TestIPv6(t *testing.T) {
	g := mustGuard(t, []string{"2001:db8::/32"}, nil)
	wantAllow(t, g, "2001:db8::1")
	wantAllow(t, g, "[2001:db8::1]:8443")
	wantDeny(t, g, "2001:db9::1", ReasonNotInScope)
}

func TestPortPolicy(t *testing.T) {
	// Without an explicit port: all ports are covered.
	g := mustGuard(t, []string{"acme.io"}, nil)
	wantAllow(t, g, "acme.io")
	wantAllow(t, g, "acme.io:8443")
	wantAllow(t, g, "https://acme.io:8443/x")

	// With an explicit port: only that port.
	g2 := mustGuard(t, []string{"acme.io:443"}, nil)
	wantAllow(t, g2, "acme.io:443")
	wantDeny(t, g2, "acme.io:8443", ReasonNotInScope)
	wantDeny(t, g2, "acme.io", ReasonNotInScope) // without a port != port 443
}

func TestURLPrefixSegmentBoundary(t *testing.T) {
	g := mustGuard(t, []string{"https://acme.io/api/"}, nil)
	wantAllow(t, g, "https://acme.io/api")
	wantAllow(t, g, "https://acme.io/api/v1/users")
	wantAllow(t, g, "https://acme.io/api/../api/x") // the path is normalized first
	wantDeny(t, g, "https://acme.io/apixyz", ReasonNotInScope)
	wantDeny(t, g, "https://acme.io/", ReasonNotInScope)
	wantDeny(t, g, "https://other.io/api", ReasonNotInScope)
}

func TestURLPrefixTraversalCannotEscape(t *testing.T) {
	g := mustGuard(t, []string{"https://acme.io/api/"}, nil)
	// ".." must not leave the prefix to reach /admin.
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
		t.Fatalf("want 3 errors (a.*.io, empty entry, ***), got %d: %v", len(errs), errs)
	}
}

func TestUnparseableOutOfScopeSurfaced(t *testing.T) {
	// An out-of-scope entry that fails to parse MUST surface as an error (under-block is dangerous).
	_, errs := New([]string{"acme.io"}, []string{"a.*.io"})
	if len(errs) == 0 {
		t.Fatal("an unparsed out-of-scope entry must surface an error")
	}
	if !strings.Contains(errs[0].Error(), "out-of-scope") {
		t.Errorf("the error must mark the out-of-scope side: %v", errs[0])
	}
}

func TestResultTargetNormalized(t *testing.T) {
	g := mustGuard(t, []string{"acme.io"}, nil)
	r := g.Evaluate("https://user:pass@ACME.io.:443/a/../b")
	if r.Target != "acme.io:443/b" {
		t.Errorf("normalized Target = %q, want acme.io:443/b", r.Target)
	}
}

func TestURLPrefixOnIPHost(t *testing.T) {
	g := mustGuard(t, []string{"http://203.0.113.10/app"}, nil)
	wantAllow(t, g, "http://203.0.113.10/app/x")
	wantDeny(t, g, "http://203.0.113.10/other", ReasonNotInScope)
	wantDeny(t, g, "http://203.0.113.11/app", ReasonNotInScope)
	wantDeny(t, g, "203.0.113.10", ReasonNotInScope) // path "/" is not under /app
}

// The effective port is computed from the scheme; an allow still needs evidence when unknown.
func TestEffectivePortFromScheme(t *testing.T) {
	g := mustGuard(t, []string{"https://acme.io:443/"}, nil)
	wantAllow(t, g, "https://acme.io/x")
	wantAllow(t, g, "wss://acme.io/x")
	wantDeny(t, g, "http://acme.io/x", ReasonNotInScope)
	wantDeny(t, g, "ftp://acme.io/x", ReasonNotInScope)
	wantDeny(t, g, "acme.io", ReasonNotInScope)

	r := g.Evaluate("https://acme.io/x")
	if r.Target != "acme.io/x" {
		t.Errorf("Target = %q: the effective port must not change the audit form", r.Target)
	}
}

func TestPathScoped(t *testing.T) {
	g := mustGuard(t, []string{"*.acme.io", "acme.io", "203.0.113.0/24", "https://api.acme.io/v1"},
		[]string{"https://app.acme.io/admin", "shop.acme.io/cart", "https://port.acme.io:8443/x", "http://203.0.113.10/admin",
			"root.acme.io", "https://slash.acme.io/", "off.acme.io:8080", "*.dev.acme.io"})
	cases := map[string]bool{
		"app.acme.io:443":   true,  // path-based exclusion with a scheme
		"app.acme.io:8443":  true,  // an entry without a port applies to all ports
		"APP.acme.io:443":   true,  // host normalized
		"shop.acme.io:443":  true,  // schemeless form, the importer output
		"port.acme.io:8443": true,  // port matches
		"port.acme.io:443":  false, // the exclusion is only for another port
		"port.acme.io":      true,  // unknown port: in doubt means open
		"203.0.113.10:443":  true,  // host IP
		"203.0.113.11:443":  false, // another IP
		"acme.io:443":       false, // another host, no path-based exclusion
		"root.acme.io:443":  false, // a host exclusion without a path is enough at CONNECT
		"slash.acme.io:443": false, // a root path equals the whole host
		"off.acme.io:80":    false, // a ported exclusion without a path
		"x.dev.acme.io:443": false, // a wildcard has no path
		"api.acme.io:443":   false, // an in-scope path entry is not an exclusion
		"acme.io:notaport":  true,  // unparsed: in doubt means open
		"":                  true,
	}
	for target, want := range cases {
		if got := g.PathScoped(target); got != want {
			t.Errorf("PathScoped(%q) = %v, want %v", target, got, want)
		}
	}
}

// The gap-closing invariant: a URL the guard denies must not have a host:port that
// passes CONNECT without being opened, because a blind tunnel cannot block it.
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
					continue // CONNECT itself is already denied
				}
				for _, scheme := range []string{"http", "https"} {
					for _, p := range paths {
						u := scheme + "://" + a + p
						if r := g.Evaluate(u); !r.Allowed && r.Reason == ReasonOutOfScope {
							checked++
							if !g.PathScoped(a) {
								t.Errorf("in=%v out=%v: %s denied but %s not opened", in, out, u, a)
							}
						}
					}
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no combination tested")
	}
}
