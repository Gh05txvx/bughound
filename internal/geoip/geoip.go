// Package geoip melakukan lookup negara & ASN sebuah IP dari database MaxMind
// GeoLite2 LOKAL (.mmdb) — sepenuhnya OFFLINE, nol koneksi keluar.
//
// Ini menjaga prinsip egress-isolation BugHound (Prinsip #2): tak pernah ada
// panggilan ke layanan geolokasi pihak ketiga (ipinfo.io, ip-api.com, dll) yang
// akan berarti egress ke aset out-of-scope. Satu-satunya sumber data adalah file
// .mmdb yang operator sediakan sendiri.
//
// Fitur ini OPSIONAL dan DEGRADASI MULUS: bila DB tak dimuat, Resolve
// mengembalikan Info kosong dan Loaded()==false — pemanggil cukup menyembunyikan
// kolom negara. Database tak pernah diperlukan agar BugHound berjalan.
package geoip

import (
	"fmt"
	"net"
	"strings"

	geoip2 "github.com/oschwald/geoip2-golang"
)

// Info adalah hasil lookup satu IP. Field kosong berarti tak diketahui.
type Info struct {
	CountryCode string // ISO-3166 alpha-2, mis. "NL"
	Country     string // nama bahasa Inggris, mis. "Netherlands"
	ASN         uint   // nomor Autonomous System, 0 bila tak diketahui
	ASNOrg      string // organisasi AS, mis. "DigitalOcean, LLC"
}

// Empty melaporkan bahwa lookup tak menghasilkan apa pun.
func (i Info) Empty() bool {
	return i.CountryCode == "" && i.Country == "" && i.ASN == 0 && i.ASNOrg == ""
}

// Flag mengembalikan emoji bendera dari CountryCode (dua Regional Indicator),
// atau "" bila kode tak valid. Murni turunan kode — tanpa data tambahan.
func (i Info) Flag() string {
	cc := strings.ToUpper(strings.TrimSpace(i.CountryCode))
	if len(cc) != 2 || cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z' {
		return ""
	}
	return string(rune(0x1F1E6+int(cc[0]-'A'))) + string(rune(0x1F1E6+int(cc[1]-'A')))
}

// Label menggabungkan nama & kode negara untuk tampilan: "Netherlands (NL)",
// atau salah satunya, atau "" bila negara tak diketahui.
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

// Display menggabungkan bendera, negara & ASN jadi satu string tampilan ringkas,
// mis. "🇳🇱 Netherlands (NL) · AS205100 — DigitalOcean, LLC". "" bila kosong.
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

// ASNLabel memformat AS untuk tampilan: "AS205100 — DigitalOcean, LLC", atau ""
// bila AS tak diketahui.
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

// Resolver memetakan IP → Info. Implementasi WAJIB offline.
type Resolver interface {
	// Resolve mengembalikan Info untuk sebuah IP (apa adanya, best-effort).
	// IP kosong/tak valid → Info kosong, tak pernah panic.
	Resolve(ip string) Info
	// Loaded melaporkan apakah setidaknya satu database termuat.
	Loaded() bool
}

// Nop adalah Resolver nonaktif: selalu Info kosong, Loaded()==false. Dipakai saat
// tak ada DB dikonfigurasi, agar pemanggil tak perlu nil-check.
type Nop struct{}

func (Nop) Resolve(string) Info { return Info{} }
func (Nop) Loaded() bool        { return false }

// DB adalah Resolver berbasis file GeoLite2 lokal. Reader maxminddb aman dibaca
// konkuren, jadi DB boleh dipakai banyak goroutine tanpa penguncian.
type DB struct {
	country *geoip2.Reader
	asn     *geoip2.Reader
}

// Open memuat database GeoLite2 Country dan/atau ASN dari path yang diberikan.
// Path kosong = lewati DB itu. Bila KEDUA path kosong, mengembalikan (nil, nil):
// pemanggil memakai Nop. Error hanya untuk path terisi yang gagal dibuka, agar
// salah konfigurasi terlihat; pemanggil boleh tetap jalan dengan Nop.
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
			return nil, fmt.Errorf("buka GeoIP Country %q: %w", countryPath, err)
		}
		db.country = r
	}
	if asnPath != "" {
		r, err := geoip2.Open(asnPath)
		if err != nil {
			db.Close()
			return nil, fmt.Errorf("buka GeoIP ASN %q: %w", asnPath, err)
		}
		db.asn = r
	}
	return db, nil
}

// Loaded melaporkan apakah setidaknya satu database termuat.
func (db *DB) Loaded() bool { return db != nil && (db.country != nil || db.asn != nil) }

// Resolve mencari negara & ASN sebuah IP. Kesalahan lookup diabaikan (field tetap
// kosong): diagnostik tak boleh gagal hanya karena satu IP tak terdaftar.
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

// Close menutup kedua reader (idempoten).
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
