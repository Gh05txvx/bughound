package geoip

import (
	"path/filepath"
	"testing"
)

func TestInfoHelpers(t *testing.T) {
	cases := []struct {
		name             string
		in               Info
		empty            bool
		flag, label, asn string
	}{
		{"kosong", Info{}, true, "", "", ""},
		{"lengkap", Info{CountryCode: "NL", Country: "Netherlands", ASN: 205100, ASNOrg: "DigitalOcean, LLC"},
			false, "\U0001F1F3\U0001F1F1", "Netherlands (NL)", "AS205100 — DigitalOcean, LLC"},
		{"hanya-kode", Info{CountryCode: "ID"}, false, "\U0001F1EE\U0001F1E9", "ID", ""},
		{"hanya-nama", Info{Country: "Germany"}, false, "", "Germany", ""},
		{"asn-tanpa-org", Info{ASN: 13335}, false, "", "", "AS13335"},
		{"asn-org-tanpa-nomor", Info{ASNOrg: "Cloudflare"}, false, "", "", "Cloudflare"},
		{"kode-invalid", Info{CountryCode: "X"}, false, "", "X", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.in.Empty(); got != c.empty {
				t.Errorf("Empty()=%v, ingin %v", got, c.empty)
			}
			if got := c.in.Flag(); got != c.flag {
				t.Errorf("Flag()=%q, ingin %q", got, c.flag)
			}
			if got := c.in.Label(); got != c.label {
				t.Errorf("Label()=%q, ingin %q", got, c.label)
			}
			if got := c.in.ASNLabel(); got != c.asn {
				t.Errorf("ASNLabel()=%q, ingin %q", got, c.asn)
			}
		})
	}
}

func TestInfoDisplay(t *testing.T) {
	cases := []struct {
		in   Info
		want string
	}{
		{Info{}, ""},
		{Info{CountryCode: "NL", Country: "Netherlands", ASN: 205100, ASNOrg: "DigitalOcean, LLC"},
			"\U0001F1F3\U0001F1F1 Netherlands (NL) · AS205100 — DigitalOcean, LLC"},
		{Info{CountryCode: "ID", Country: "Indonesia"}, "\U0001F1EE\U0001F1E9 Indonesia (ID)"},
		{Info{ASN: 13335, ASNOrg: "Cloudflare"}, "AS13335 — Cloudflare"},
		{Info{Country: "Germany"}, "Germany"},
	}
	for _, c := range cases {
		if got := c.in.Display(); got != c.want {
			t.Errorf("Display(%+v)=%q, ingin %q", c.in, got, c.want)
		}
	}
}

func TestNopResolver(t *testing.T) {
	var r Resolver = Nop{}
	if r.Loaded() {
		t.Error("Nop.Loaded() harus false")
	}
	if got := r.Resolve("8.8.8.8"); !got.Empty() {
		t.Errorf("Nop.Resolve harus kosong, dapat %+v", got)
	}
}

func TestOpenNoPathsDisabled(t *testing.T) {
	// Kedua path kosong = fitur nonaktif tanpa error (pemanggil pakai Nop).
	db, err := Open("  ", "")
	if err != nil {
		t.Fatalf("Open tanpa path harus tanpa error, dapat %v", err)
	}
	if db != nil {
		t.Errorf("Open tanpa path harus mengembalikan nil DB, dapat %+v", db)
	}
}

func TestOpenMissingFileErrors(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "tidak-ada.mmdb")
	if _, err := Open(missing, ""); err == nil {
		t.Error("Open path Country tak ada harus error")
	}
	if _, err := Open("", missing); err == nil {
		t.Error("Open path ASN tak ada harus error")
	}
}

func TestNilDBSafe(t *testing.T) {
	var db *DB
	if db.Loaded() {
		t.Error("nil DB Loaded() harus false")
	}
	if got := db.Resolve("1.1.1.1"); !got.Empty() {
		t.Errorf("nil DB Resolve harus kosong, dapat %+v", got)
	}
	if err := db.Close(); err != nil {
		t.Errorf("nil DB Close harus nil, dapat %v", err)
	}
}

func TestDBResolveBadIP(t *testing.T) {
	// DB tanpa reader (semua nil) tetap aman untuk Resolve IP valid/invalid.
	db := &DB{}
	if got := db.Resolve("bukan-ip"); !got.Empty() {
		t.Errorf("IP tak valid harus kosong, dapat %+v", got)
	}
	if got := db.Resolve("8.8.8.8"); !got.Empty() {
		t.Errorf("tanpa reader harus kosong, dapat %+v", got)
	}
	if db.Loaded() {
		t.Error("DB tanpa reader Loaded() harus false")
	}
}
