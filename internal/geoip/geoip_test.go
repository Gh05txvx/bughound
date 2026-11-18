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
		{"empty", Info{}, true, "", "", ""},
		{"full", Info{CountryCode: "NL", Country: "Netherlands", ASN: 205100, ASNOrg: "DigitalOcean, LLC"},
			false, "\U0001F1F3\U0001F1F1", "Netherlands (NL)", "AS205100 — DigitalOcean, LLC"},
		{"code-only", Info{CountryCode: "ID"}, false, "\U0001F1EE\U0001F1E9", "ID", ""},
		{"name-only", Info{Country: "Germany"}, false, "", "Germany", ""},
		{"asn-without-org", Info{ASN: 13335}, false, "", "", "AS13335"},
		{"asn-org-without-number", Info{ASNOrg: "Cloudflare"}, false, "", "", "Cloudflare"},
		{"invalid-code", Info{CountryCode: "X"}, false, "", "X", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.in.Empty(); got != c.empty {
				t.Errorf("Empty()=%v, want %v", got, c.empty)
			}
			if got := c.in.Flag(); got != c.flag {
				t.Errorf("Flag()=%q, want %q", got, c.flag)
			}
			if got := c.in.Label(); got != c.label {
				t.Errorf("Label()=%q, want %q", got, c.label)
			}
			if got := c.in.ASNLabel(); got != c.asn {
				t.Errorf("ASNLabel()=%q, want %q", got, c.asn)
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
			t.Errorf("Display(%+v)=%q, want %q", c.in, got, c.want)
		}
	}
}

func TestNopResolver(t *testing.T) {
	var r Resolver = Nop{}
	if r.Loaded() {
		t.Error("Nop.Loaded() must be false")
	}
	if got := r.Resolve("8.8.8.8"); !got.Empty() {
		t.Errorf("Nop.Resolve must be empty, got %+v", got)
	}
}

func TestOpenNoPathsDisabled(t *testing.T) {
	// Both paths empty = the feature is off with no error (the caller uses Nop).
	db, err := Open("  ", "")
	if err != nil {
		t.Fatalf("Open without paths must not error, got %v", err)
	}
	if db != nil {
		t.Errorf("Open without paths must return a nil DB, got %+v", db)
	}
}

func TestOpenMissingFileErrors(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.mmdb")
	if _, err := Open(missing, ""); err == nil {
		t.Error("Open with a missing Country path must error")
	}
	if _, err := Open("", missing); err == nil {
		t.Error("Open with a missing ASN path must error")
	}
}

func TestNilDBSafe(t *testing.T) {
	var db *DB
	if db.Loaded() {
		t.Error("nil DB Loaded() must be false")
	}
	if got := db.Resolve("1.1.1.1"); !got.Empty() {
		t.Errorf("nil DB Resolve must be empty, got %+v", got)
	}
	if err := db.Close(); err != nil {
		t.Errorf("nil DB Close must be nil, got %v", err)
	}
}

func TestDBResolveBadIP(t *testing.T) {
	// A DB with no readers (all nil) is still safe to Resolve a valid or invalid IP.
	db := &DB{}
	if got := db.Resolve("not-an-ip"); !got.Empty() {
		t.Errorf("an invalid IP must be empty, got %+v", got)
	}
	if got := db.Resolve("8.8.8.8"); !got.Empty() {
		t.Errorf("without readers the result must be empty, got %+v", got)
	}
	if db.Loaded() {
		t.Error("a DB without readers must report Loaded() false")
	}
}
