// Package geoip looks up the country and ASN of an IP in a LOCAL MaxMind
// GeoLite2 database (.mmdb). It is fully OFFLINE and makes no outbound
// connections.
//
// This keeps BugHound's egress isolation principle (Principle #2): there is
// never a call to a third-party geolocation service (ipinfo.io, ip-api.com,
// etc.), which would be egress to an out-of-scope asset. The only data source
// is the .mmdb file the operator supplies.
//
// The feature is OPTIONAL and DEGRADES CLEANLY: when no DB is loaded, Resolve
// returns an empty Info and Loaded()==false, and the caller only has to hide
// the country column. BugHound never needs the database to run.
package geoip

import (
	"fmt"
	"net"
	"strings"

	geoip2 "github.com/oschwald/geoip2-golang"
)

// Info is the lookup result for one IP. An empty field means unknown.
type Info struct {
	CountryCode string // ISO-3166 alpha-2, mis. "NL"
	Country     string // English name, e.g. "Netherlands"
	ASN         uint   // Autonomous System number, 0 when unknown
	ASNOrg      string // AS organization, e.g. "DigitalOcean, LLC"
}

// Empty reports that the lookup returned nothing.
func (i Info) Empty() bool {
	return i.CountryCode == "" && i.Country == "" && i.ASN == 0 && i.ASNOrg == ""
}

// Flag returns the flag emoji for CountryCode (two Regional Indicators), or ""
// when the code is invalid. It is derived from the code alone, with no extra data.
func (i Info) Flag() string {
	cc := strings.ToUpper(strings.TrimSpace(i.CountryCode))
	if len(cc) != 2 || cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z' {
		return ""
	}
	return string(rune(0x1F1E6+int(cc[0]-'A'))) + string(rune(0x1F1E6+int(cc[1]-'A')))
}

// Label joins the country name and code for display: "Netherlands (NL)", or
// whichever one is set, or "" when the country is unknown.
func (i Info) Label() string {
	switch {
	case i.Country != "" && i.CountryCode != "":
		return i.Country + " (" + i.CountryCode + ")"
	case i.Country != "":
		return i.Country
	default:
		return i.CountryCode
	}
}

// Display joins the flag, country and ASN into one short display string, e.g.
// "🇳🇱 Netherlands (NL) · AS205100 — DigitalOcean, LLC". "" when empty.
func (i Info) Display() string {
	var parts []string
	if loc := strings.TrimSpace(i.Flag() + " " + i.Label()); loc != "" {
		parts = append(parts, loc)
	}
	if a := i.ASNLabel(); a != "" {
		parts = append(parts, a)
	}
	return strings.Join(parts, " · ")
}

// ASNLabel formats the AS for display: "AS205100 — DigitalOcean, LLC", or ""
// when the AS is unknown.
func (i Info) ASNLabel() string {
	if i.ASN == 0 && i.ASNOrg == "" {
		return ""
	}
	if i.ASN == 0 {
		return i.ASNOrg
	}
	s := fmt.Sprintf("AS%d", i.ASN)
	if i.ASNOrg != "" {
		s += " — " + i.ASNOrg
	}
	return s
}

// Resolver maps IP → Info. Implementations MUST be offline.
type Resolver interface {
	// Resolve returns the Info for an IP (as is, best effort).
	// An empty or invalid IP → an empty Info; it never panics.
	Resolve(ip string) Info
	// Loaded reports whether at least one database is loaded.
	Loaded() bool
}

// Nop is the disabled Resolver: always an empty Info, Loaded()==false. It is
// used when no DB is configured, so callers need no nil check.
type Nop struct{}

func (Nop) Resolve(string) Info { return Info{} }
func (Nop) Loaded() bool        { return false }

// DB is a Resolver backed by local GeoLite2 files. A maxminddb reader is safe
// for concurrent reads, so many goroutines can share a DB without locking.
type DB struct {
	country *geoip2.Reader
	asn     *geoip2.Reader
}

// Open loads the GeoLite2 Country and/or ASN database from the given paths. An
// empty path skips that DB. When BOTH paths are empty it returns (nil, nil) and
// the caller uses Nop. It errors only for a non-empty path that fails to open,
// so a misconfiguration is visible; the caller may still carry on with Nop.
func Open(countryPath, asnPath string) (*DB, error) {
	countryPath = strings.TrimSpace(countryPath)
	asnPath = strings.TrimSpace(asnPath)
	if countryPath == "" && asnPath == "" {
		return nil, nil
	}
	db := &DB{}
	if countryPath != "" {
		r, err := geoip2.Open(countryPath)
		if err != nil {
			return nil, fmt.Errorf("open GeoIP Country %q: %w", countryPath, err)
		}
		db.country = r
	}
	if asnPath != "" {
		r, err := geoip2.Open(asnPath)
		if err != nil {
			db.Close()
			return nil, fmt.Errorf("open GeoIP ASN %q: %w", asnPath, err)
		}
		db.asn = r
	}
	return db, nil
}

// Loaded reports whether at least one database is loaded.
func (db *DB) Loaded() bool { return db != nil && (db.country != nil || db.asn != nil) }

// Resolve looks up the country and ASN of an IP. Lookup errors are ignored (the
// fields stay empty): diagnostics must not fail because one IP is not listed.
func (db *DB) Resolve(ip string) Info {
	var info Info
	if db == nil {
		return info
	}
	addr := net.ParseIP(strings.TrimSpace(ip))
	if addr == nil {
		return info
	}
	if db.country != nil {
		if rec, err := db.country.Country(addr); err == nil {
			info.CountryCode = rec.Country.IsoCode
			info.Country = rec.Country.Names["en"]
		}
	}
	if db.asn != nil {
		if rec, err := db.asn.ASN(addr); err == nil {
			info.ASN = rec.AutonomousSystemNumber
			info.ASNOrg = rec.AutonomousSystemOrganization
		}
	}
	return info
}

// Close closes both readers (idempotent).
func (db *DB) Close() error {
	if db == nil {
		return nil
	}
	if db.country != nil {
		_ = db.country.Close()
		db.country = nil
	}
	if db.asn != nil {
		_ = db.asn.Close()
		db.asn = nil
	}
	return nil
}
