package scope

import "testing"

// Pengujian audit (BH-P03-APPSEC): baterai percobaan bypass scope guard dengan
// target dummy. Tujuannya menekan kontrol #1 sekeras mungkin — semua harus
// berakhir TOLAK, dan target sah tetap IZIN.

func TestAudit_ScopeBypassAttemptsDenied(t *testing.T) {
	g := mustGuard(t,
		[]string{"app.acme.io", "*.corp.acme.io", "203.0.113.0/24"},
		[]string{"secret.corp.acme.io"},
	)

	mustDeny := []struct{ target, why string }{
		{"evil.com", "domain lain"},
		{"app.acme.io.evil.com", "suffix palsu"},
		{"notapp.acme.io", "bukan subdomain in-scope"},
		{"acme.io", "apex tak terdaftar"},
		{"corp.acme.io", "apex wildcard tak tercakup"},
		{"аpp.acme.io", "homoglyph Cyrillic 'а'"},
		{"http://app.acme.io@evil.com/", "userinfo menyamarkan host (host asli evil.com)"},
		{"http://user:pass@evil.com/app.acme.io", "userinfo + path tipuan"},
		{"169.254.169.254", "metadata cloud, tak eksplisit in-scope"},
		{"http://169.254.169.254/latest/meta-data/", "SSRF metadata via URL"},
		{"10.0.0.1", "IP privat tak in-scope"},
		{"0x7f.0.0.1", "IP heksadesimal menyesatkan"},
		{"2130706433", "IP desimal menyesatkan"},
		{"203.0.114.1", "di luar CIDR in-scope"},
		{"secret.corp.acme.io", "out-of-scope menang atas wildcard"},
		{"", "target kosong (fail closed)"},
		{"http://", "URL tanpa host (fail closed)"},
		{"ht!tp://a b c", "sampah (fail closed)"},
	}
	for _, tc := range mustDeny {
		if r := g.Evaluate(tc.target); r.Allowed {
			t.Errorf("BYPASS: %q seharusnya DITOLAK (%s), tapi diizinkan (reason=%s, entry=%s)",
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
		"https://APP.acme.io./dashboard", // huruf besar + titik akhir dinormalkan
		"http://app.acme.io:8443/",       // kebijakan port: host mencakup semua port
	}
	for _, tgt := range mustAllow {
		if r := g.Evaluate(tgt); !r.Allowed {
			t.Errorf("FALSE DENY: %q seharusnya diizinkan, tapi ditolak (reason=%s)", tgt, r.Reason)
		}
	}
}

// BH-F04: target dengan karakter authority berbahaya ditolak (tutup celah
// parser-differential, mis. backslash).
func TestAudit_SuspiciousCharsRejected(t *testing.T) {
	g := mustGuard(t, []string{"app.acme.io"}, nil)
	for _, tgt := range []string{
		"http://evil.com\\@app.acme.io/", // backslash: parser lain bisa anggap host=evil.com
		"ap p.acme.io",                   // spasi internal
		"ap\tp.acme.io",                  // tab internal
		"http://app.acme.io\r\nevil",     // injeksi CRLF
		"app.acme.io\x00",                // null byte
	} {
		if g.Evaluate(tgt).Allowed {
			t.Errorf("target dengan karakter mencurigakan harus ditolak: %q", tgt)
		}
	}
}

func TestAudit_SurroundingWhitespaceTrimmed(t *testing.T) {
	g := mustGuard(t, []string{"app.acme.io"}, nil)
	for _, tgt := range []string{" app.acme.io", "app.acme.io ", "\tapp.acme.io\n"} {
		if !g.Evaluate(tgt).Allowed {
			t.Errorf("spasi di tepi harus di-trim & diizinkan: %q", tgt)
		}
	}
}

// Metadata/IP privat hanya boleh bila eksplisit di-scope lewat IP/CIDR.
func TestAudit_PrivateMetadataOnlyWhenExplicit(t *testing.T) {
	deny := mustGuard(t, []string{"*.acme.io"}, nil)
	for _, ip := range []string{"169.254.169.254", "10.1.2.3", "192.168.0.1", "127.0.0.1"} {
		if deny.Evaluate(ip).Allowed {
			t.Errorf("IP privat/metadata %q tak boleh lolos via scope hostname", ip)
		}
	}
	allow := mustGuard(t, []string{"169.254.169.254", "10.0.0.0/8"}, nil)
	for _, ip := range []string{"169.254.169.254", "10.1.2.3"} {
		if !allow.Evaluate(ip).Allowed {
			t.Errorf("IP %q eksplisit in-scope seharusnya diizinkan", ip)
		}
	}
	if allow.Evaluate("192.168.0.1").Allowed {
		t.Error("192.168.0.1 di luar CIDR eksplisit tak boleh lolos")
	}
}

// Eksklusi yang diam-diam tak cocok berarti aset terlarang tersentuh, melanggar
// "out-of-scope menang". Tiap bentuk di bawah pernah lolos dari guard.
func TestAudit_ExclusionFormsEnforced(t *testing.T) {
	cidr := []string{"203.0.113.0/24"}
	host := []string{"acme.io"}
	cases := []struct {
		name        string
		in, out     []string
		deny, allow []string
	}{
		{
			name: "URL ber-host IP dengan path", in: cidr, out: []string{"https://203.0.113.10/admin"},
			deny:  []string{"https://203.0.113.10/admin", "https://203.0.113.10/admin/x", "http://203.0.113.10:8080/admin"},
			allow: []string{"https://203.0.113.10/shop", "https://203.0.113.11/admin"},
		},
		{
			name: "URL ber-host IP pada root", in: cidr, out: []string{"http://203.0.113.10/"},
			deny:  []string{"203.0.113.10", "https://203.0.113.10/x", "203.0.113.10:8080"},
			allow: []string{"203.0.113.11"},
		},
		{
			name: "URL berport, target tanpa port", in: host, out: []string{"https://acme.io:443/admin"},
			deny:  []string{"https://acme.io/admin", "https://acme.io:443/admin/x", "acme.io/admin"},
			allow: []string{"http://acme.io/admin", "https://acme.io:8443/admin", "https://acme.io/shop"},
		},
		{
			name: "host berport HTTP", in: host, out: []string{"acme.io:80"},
			deny:  []string{"http://acme.io/x", "acme.io:80", "acme.io"},
			allow: []string{"https://acme.io/x", "acme.io:443"},
		},
		{
			name: "IP berport", in: cidr, out: []string{"203.0.113.10:443"},
			deny:  []string{"https://203.0.113.10/", "203.0.113.10:443", "203.0.113.10"},
			allow: []string{"http://203.0.113.10/", "203.0.113.10:8080"},
		},
		{
			name: "port bernol di depan pada target", in: host, out: []string{"acme.io:443"},
			deny:  []string{"https://acme.io:0443/x", "acme.io:00443"},
			allow: []string{"https://acme.io:8443/x"},
		},
		{
			name: "port bernol di depan pada entri", in: host, out: []string{"acme.io:0443"},
			deny:  []string{"https://acme.io/x", "acme.io:443"},
			allow: []string{"http://acme.io/x"},
		},
		{
			name: "IP bertitik akhir", in: cidr, out: []string{"203.0.113.10."},
			deny:  []string{"203.0.113.10", "https://203.0.113.10/x"},
			allow: []string{"203.0.113.11"},
		},
		{
			name: "IP berdigit fullwidth", in: cidr, out: []string{"２０３.０.１１３.１０"},
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

// Target IP tersamar ditolak walau IP-nya in-scope: engine akan me-resolve-nya
// lewat DNS, jadi tujuannya tak terbukti IP yang dinilai guard.
func TestAudit_TargetIPDisguisedAsHost(t *testing.T) {
	g := mustGuard(t, []string{"203.0.113.0/24"}, []string{"203.0.113.10"})
	for _, target := range []string{
		"203.0.113.11.", "http://203.0.113.11./x", "２０３.０.１１３.１１", "203.0.113.10.",
	} {
		wantDeny(t, g, target, ReasonParseError)
	}
	wantAllow(t, g, "203.0.113.11")
}

// Entri yang tak pernah cocok target ditolak saat input, bukan diam-diam mati.
func TestAudit_MeaninglessEntriesRejected(t *testing.T) {
	for _, raw := range []string{
		"mailto:a@acme.io", "acme.io:abc", "acme.io:0", "acme.io:65536", "http://acme.io:99999/",
		"10.0.0.1-50", "10.0.0.1-10.0.0.50", "http://10.0.0.1-50/",
		".acme.io", "acme..io", "acme.io..", "*..acme.io",
		"203.0.113.10/33", "203.0.113.0/24:443", "203.0.113.10/admin",
	} {
		if _, errs := New(nil, []string{raw}); len(errs) == 0 {
			t.Errorf("entri %q harus ditolak saat input", raw)
		}
	}
}

// Pengetatan di atas tak boleh mengenai bentuk sah, termasuk nama lab.
func TestAudit_LegitimateEntriesStillAccepted(t *testing.T) {
	for _, raw := range []string{
		"localhost", "juice-shop", "app.internal", "demo.test", "acme.io:8443", "acme.io.",
		"203.0.113.10/", "172.30.0.0/24", "http://203.0.113.10/app", "[2001:db8::1]:8443",
		"203.0.113.10-static.isp.example", "1-2-3-4.isp.example",
	} {
		if _, errs := New([]string{raw}, nil); len(errs) > 0 {
			t.Errorf("entri sah %q ditolak: %v", raw, errs)
		}
	}
}

func TestAudit_InvalidTargetFailsClosed(t *testing.T) {
	g := mustGuard(t, []string{"acme.io"}, nil)
	for _, target := range []string{"acme.io:abc", "acme.io:0", "acme.io:65536", "http://.acme.io/", "acme..io"} {
		wantDeny(t, g, target, ReasonParseError)
	}
}
