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
