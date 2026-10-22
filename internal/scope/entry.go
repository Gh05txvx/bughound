package scope

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

// entryKind adalah bentuk entri scope yang didukung v1. Bentuk lain (mis. regex
// bebas) tidak didukung dan ditolak saat parsing, bukan ditebak maknanya.
type entryKind int

const (
	kindHostExact entryKind = iota // app.acme.io
	kindWildcard                   // *.acme.io
	kindURLPrefix                  // https://acme.io/api/  atau acme.io/api
	kindIP                         // 203.0.113.10
	kindCIDR                       // 203.0.113.0/24
)

// entry adalah satu aturan scope yang sudah dinormalkan.
type entry struct {
	raw  string
	kind entryKind

	host string       // host punycode (kindHostExact, kindURLPrefix)
	base string       // basis wildcard tanpa "*." (kindWildcard)
	port string       // port eksplisit, "" = semua port (kebijakan v1)
	path string       // prefix path ternormalkan (kindURLPrefix)
	addr netip.Addr   // kindIP
	cidr netip.Prefix // kindCIDR
}

// parseEntry mengurai satu string scope menjadi entry. Pencocokan dilakukan
// positif per-bentuk: apa pun yang tidak cocok bentuk yang didukung ditolak.
func parseEntry(raw string) (entry, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return entry{}, errors.New("entri kosong")
	}
	if hasSuspiciousChars(s) {
		return entry{}, fmt.Errorf("entri scope mengandung karakter terlarang (backslash/spasi/kontrol): %q", raw)
	}

	// 1. Wildcard subdomain: hanya di posisi paling kiri.
	if strings.HasPrefix(s, "*.") {
		base := strings.TrimPrefix(s, "*.")
		if base == "" || strings.Contains(base, "*") {
			return entry{}, fmt.Errorf("wildcard hanya di subdomain paling kiri: %q", raw)
		}
		nb, err := normalizeHost(base)
		if err != nil {
			return entry{}, fmt.Errorf("%q: %w", raw, err)
		}
		return entry{raw: raw, kind: kindWildcard, base: nb}, nil
	}
	if strings.Contains(s, "*") {
		return entry{}, fmt.Errorf("bentuk wildcard tak didukung (hanya *.domain): %q", raw)
	}

	// 2. URL / prefix path dengan skema.
	if strings.Contains(s, "://") {
		return parseURLEntry(raw, s)
	}

	// 3. CIDR.
	if p, err := netip.ParsePrefix(s); err == nil {
		return entry{raw: raw, kind: kindCIDR, cidr: p.Masked()}, nil
	}

	// 4. host/path tanpa skema (mengandung "/").
	if i := strings.IndexByte(s, '/'); i >= 0 {
		host, port, err := splitHostPort(s[:i])
		if err != nil {
			return entry{}, fmt.Errorf("%q: %w", raw, err)
		}
		nh, err := normalizeHost(host)
		if err != nil {
			return entry{}, fmt.Errorf("%q: %w", raw, err)
		}
		return entry{raw: raw, kind: kindURLPrefix, host: nh, port: port, path: normalizePath(s[i:])}, nil
	}

	// 5. IP mentah.
	if addr, err := netip.ParseAddr(s); err == nil {
		return entry{raw: raw, kind: kindIP, addr: addr}, nil
	}

	// 6. host[:port] atau ip:port.
	host, port, err := splitHostPort(s)
	if err != nil {
		return entry{}, fmt.Errorf("entri scope tak dikenali: %q", raw)
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return entry{raw: raw, kind: kindIP, addr: addr, port: port}, nil
	}
	nh, err := normalizeHost(host)
	if err != nil {
		return entry{}, fmt.Errorf("%q: %w", raw, err)
	}
	return entry{raw: raw, kind: kindHostExact, host: nh, port: port}, nil
}

func parseURLEntry(raw, s string) (entry, error) {
	u, err := url.Parse(s)
	if err != nil {
		return entry{}, fmt.Errorf("URL scope tak valid %q: %w", raw, err)
	}
	if u.Host == "" {
		return entry{}, fmt.Errorf("URL scope tanpa host: %q", raw)
	}
	host, port := u.Hostname(), u.Port()
	if addr, err := netip.ParseAddr(host); err == nil {
		// URL berhost IP: simpan bentuk kanonik IP sebagai host-string.
		return entry{raw: raw, kind: kindURLPrefix, host: addr.String(), port: port, path: normalizePath(u.Path)}, nil
	}
	nh, err := normalizeHost(host)
	if err != nil {
		return entry{}, fmt.Errorf("%q: %w", raw, err)
	}
	return entry{raw: raw, kind: kindURLPrefix, host: nh, port: port, path: normalizePath(u.Path)}, nil
}

// matches melaporkan apakah target t cocok dengan entri ini. Target hostname
// hanya cocok dengan entri berbasis host; target IP hanya cocok dengan entri
// IP/CIDR (tidak ada resolusi DNS di v1).
func (e entry) matches(t normTarget) bool {
	switch e.kind {
	case kindIP:
		return t.isIP && t.addr == e.addr && portOK(e.port, t.port)
	case kindCIDR:
		return t.isIP && e.cidr.Contains(t.addr)
	case kindHostExact:
		return !t.isIP && t.host == e.host && portOK(e.port, t.port)
	case kindWildcard:
		return !t.isIP && isSubdomain(t.host, e.base)
	case kindURLPrefix:
		return !t.isIP && t.host == e.host && portOK(e.port, t.port) && pathUnder(e.path, t.path)
	}
	return false
}

// portOK menerapkan kebijakan port v1: scope berbasis host mencakup semua port
// kecuali entri menyebut port eksplisit.
func portOK(entryPort, targetPort string) bool {
	if entryPort == "" {
		return true
	}
	return entryPort == targetPort
}

// isSubdomain melaporkan apakah host adalah subdomain sejati dari base. Apex
// (host == base) sengaja TIDAK tercakup wildcard (BH-SPEC-SCOPE). Perbandingan
// pada batas label mencegah "acme.io.evil.com" cocok dengan base "acme.io".
func isSubdomain(host, base string) bool {
	if host == base {
		return false
	}
	return strings.HasSuffix(host, "."+base)
}

// pathUnder melaporkan apakah target path berada di bawah prefix pada batas
// segmen (bukan sekadar awalan string): prefix "/api" mencakup "/api" dan
// "/api/v1", tapi bukan "/apixyz".
func pathUnder(prefix, target string) bool {
	if prefix == "" || prefix == "/" {
		return true
	}
	return target == prefix || strings.HasPrefix(target, prefix+"/")
}
