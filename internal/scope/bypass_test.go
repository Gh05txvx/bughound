package scope

import "testing"

// Audit test (BH-P03-APPSEC): a battery of scope-guard bypass attempts against
// a dummy target. The point is to press control #1 as hard as possible — every one must
// end in DENY, and a valid target must still be ALLOWED.

func TestAudit_ScopeBypassAttemptsDenied(t *testing.T) {
	g := mustGuard(t,
		[]string{"app.acme.io", "*.corp.acme.io", "203.0.113.0/24"},
		[]string{"secret.corp.acme.io"},
	)

	mustDeny := []struct{ target, why string }{
		{"evil.com", "another domain"},
		{"app.acme.io.evil.com", "fake suffix"},
		{"notapp.acme.io", "not an in-scope subdomain"},
		{"acme.io", "unlisted apex"},
		{"corp.acme.io", "apex not covered by the wildcard"},
		{"аpp.acme.io", "homoglyph Cyrillic 'а'"},
		{"http://app.acme.io@evil.com/", "userinfo disguises the host (real host evil.com)"},
		{"http://user:pass@evil.com/app.acme.io", "userinfo + decoy path"},
		{"169.254.169.254", "cloud metadata, not explicitly in-scope"},
		{"http://169.254.169.254/latest/meta-data/", "SSRF metadata via URL"},
		{"10.0.0.1", "private IP not in-scope"},
		{"0x7f.0.0.1", "misleading hexadecimal IP"},
		{"2130706433", "misleading decimal IP"},
		{"203.0.114.1", "outside the in-scope CIDR"},
		{"secret.corp.acme.io", "out-of-scope wins over the wildcard"},
		{"", "empty target (fail closed)"},
		{"http://", "URL without a host (fail closed)"},
		{"ht!tp://a b c", "garbage (fail closed)"},
	}
	for _, tc := range mustDeny {
		if r := g.Evaluate(tc.target); r.Allowed {
			t.Errorf("BYPASS: %q should be DENIED (%s), but was allowed (reason=%s, entry=%s)",
				tc.target, tc.why, r.Reason, r.MatchedEntry)
		}
	}
}

func TestAudit_LegitimateTargetsAllowed(t *testing.T) {
	g := mustGuard(t,
		[]string{"app.acme.io", "*.corp.acme.io", "203.0.113.0/24"},
		[]string{"secret.corp.acme.io"},
	)
	mustAllow := []string{
		"app.acme.io",
		"x.corp.acme.io",
		"a.b.corp.acme.io",
		"203.0.113.5",
		"https://APP.acme.io./dashboard", // uppercase + trailing dot normalized
		"http://app.acme.io:8443/",       // port policy: a host covers all ports
	}
	for _, tgt := range mustAllow {
		if r := g.Evaluate(tgt); !r.Allowed {
			t.Errorf("FALSE DENY: %q should be allowed, but was denied (reason=%s)", tgt, r.Reason)
		}
	}
}

// BH-F04: a target with dangerous authority characters is denied (closes the
// parser-differential gap, e.g. a backslash).
func TestAudit_SuspiciousCharsRejected(t *testing.T) {
	g := mustGuard(t, []string{"app.acme.io"}, nil)
	for _, tgt := range []string{
		"http://evil.com\\@app.acme.io/", // backslash: another parser may read host=evil.com
		"ap p.acme.io",                   // internal space
		"ap\tp.acme.io",                  // tab internal
		"http://app.acme.io\r\nevil",     // CRLF injection
		"app.acme.io\x00",                // null byte
	} {
		if g.Evaluate(tgt).Allowed {
			t.Errorf("a target with suspicious characters must be denied: %q", tgt)
		}
	}
}

func TestAudit_SurroundingWhitespaceTrimmed(t *testing.T) {
	g := mustGuard(t, []string{"app.acme.io"}, nil)
	for _, tgt := range []string{" app.acme.io", "app.acme.io ", "\tapp.acme.io\n"} {
		if !g.Evaluate(tgt).Allowed {
			t.Errorf("edge whitespace must be trimmed & allowed: %q", tgt)
		}
	}
}

// Metadata/private IP is allowed only when explicitly scoped through IP/CIDR.
func TestAudit_PrivateMetadataOnlyWhenExplicit(t *testing.T) {
	deny := mustGuard(t, []string{"*.acme.io"}, nil)
	for _, ip := range []string{"169.254.169.254", "10.1.2.3", "192.168.0.1", "127.0.0.1"} {
		if deny.Evaluate(ip).Allowed {
			t.Errorf("private/metadata IP %q must not pass through a hostname scope", ip)
		}
	}
	allow := mustGuard(t, []string{"169.254.169.254", "10.0.0.0/8"}, nil)
	for _, ip := range []string{"169.254.169.254", "10.1.2.3"} {
		if !allow.Evaluate(ip).Allowed {
			t.Errorf("IP %q explicitly in-scope should be allowed", ip)
		}
	}
	if allow.Evaluate("192.168.0.1").Allowed {
		t.Error("192.168.0.1 outside the explicit CIDR must not pass")
	}
}

// An exclusion that silently fails to match means a forbidden asset is touched, breaking
// "out-of-scope wins". Each form below once slipped past the guard.
func TestAudit_ExclusionFormsEnforced(t *testing.T) {
	cidr := []string{"203.0.113.0/24"}
	host := []string{"acme.io"}
	cases := []struct {
		name        string
		in, out     []string
		deny, allow []string
	}{
		{
			name: "URL with an IP host and a path", in: cidr, out: []string{"https://203.0.113.10/admin"},
			deny:  []string{"https://203.0.113.10/admin", "https://203.0.113.10/admin/x", "http://203.0.113.10:8080/admin"},
			allow: []string{"https://203.0.113.10/shop", "https://203.0.113.11/admin"},
		},
		{
			name: "URL with an IP host at the root", in: cidr, out: []string{"http://203.0.113.10/"},
			deny:  []string{"203.0.113.10", "https://203.0.113.10/x", "203.0.113.10:8080"},
			allow: []string{"203.0.113.11"},
		},
		{
			name: "URL with a port, target without a port", in: host, out: []string{"https://acme.io:443/admin"},
			deny:  []string{"https://acme.io/admin", "https://acme.io:443/admin/x", "acme.io/admin"},
			allow: []string{"http://acme.io/admin", "https://acme.io:8443/admin", "https://acme.io/shop"},
		},
		{
			name: "host with an HTTP port", in: host, out: []string{"acme.io:80"},
			deny:  []string{"http://acme.io/x", "acme.io:80", "acme.io"},
			allow: []string{"https://acme.io/x", "acme.io:443"},
		},
		{
			name: "IP with a port", in: cidr, out: []string{"203.0.113.10:443"},
			deny:  []string{"https://203.0.113.10/", "203.0.113.10:443", "203.0.113.10"},
			allow: []string{"http://203.0.113.10/", "203.0.113.10:8080"},
		},
		{
			name: "leading-zero port on the target", in: host, out: []string{"acme.io:443"},
			deny:  []string{"https://acme.io:0443/x", "acme.io:00443"},
			allow: []string{"https://acme.io:8443/x"},
		},
		{
			name: "leading-zero port on the entry", in: host, out: []string{"acme.io:0443"},
			deny:  []string{"https://acme.io/x", "acme.io:443"},
			allow: []string{"http://acme.io/x"},
		},
		{
			name: "IP with a trailing dot", in: cidr, out: []string{"203.0.113.10."},
			deny:  []string{"203.0.113.10", "https://203.0.113.10/x"},
			allow: []string{"203.0.113.11"},
		},
		{
			name: "IP with fullwidth digits", in: cidr, out: []string{"２０３.０.１１３.１０"},
			deny:  []string{"203.0.113.10", "https://203.0.113.10/x"},
			allow: []string{"203.0.113.11"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := mustGuard(t, c.in, c.out)
			for _, target := range c.deny {
				wantDeny(t, g, target, ReasonOutOfScope)
			}
			for _, target := range c.allow {
				wantAllow(t, g, target)
			}
		})
	}
}

// A disguised IP target is denied even though its IP is in-scope: the engine will resolve it
// through DNS, so the destination is not the proven IP the guard judged.
func TestAudit_TargetIPDisguisedAsHost(t *testing.T) {
	g := mustGuard(t, []string{"203.0.113.0/24"}, []string{"203.0.113.10"})
	for _, target := range []string{
		"203.0.113.11.", "http://203.0.113.11./x", "２０３.０.１１３.１１", "203.0.113.10.",
	} {
		wantDeny(t, g, target, ReasonParseError)
	}
	wantAllow(t, g, "203.0.113.11")
}

// An entry that never matches a target is rejected at input, not left silently dead.
func TestAudit_MeaninglessEntriesRejected(t *testing.T) {
	for _, raw := range []string{
		"mailto:a@acme.io", "acme.io:abc", "acme.io:0", "acme.io:65536", "http://acme.io:99999/",
		"10.0.0.1-50", "10.0.0.1-10.0.0.50", "http://10.0.0.1-50/",
		".acme.io", "acme..io", "acme.io..", "*..acme.io",
		"203.0.113.10/33", "203.0.113.0/24:443", "203.0.113.10/admin",
	} {
		if _, errs := New(nil, []string{raw}); len(errs) == 0 {
			t.Errorf("entry %q must be rejected at input", raw)
		}
	}
}

// The tightening above must not hit a valid form, including lab names.
func TestAudit_LegitimateEntriesStillAccepted(t *testing.T) {
	for _, raw := range []string{
		"localhost", "juice-shop", "app.internal", "demo.test", "acme.io:8443", "acme.io.",
		"203.0.113.10/", "172.30.0.0/24", "http://203.0.113.10/app", "[2001:db8::1]:8443",
		"203.0.113.10-static.isp.example", "1-2-3-4.isp.example",
	} {
		if _, errs := New([]string{raw}, nil); len(errs) > 0 {
			t.Errorf("valid entry %q was rejected: %v", raw, errs)
		}
	}
}

func TestAudit_InvalidTargetFailsClosed(t *testing.T) {
	g := mustGuard(t, []string{"acme.io"}, nil)
	for _, target := range []string{"acme.io:abc", "acme.io:0", "acme.io:65536", "http://.acme.io/", "acme..io"} {
		wantDeny(t, g, target, ReasonParseError)
	}
}
