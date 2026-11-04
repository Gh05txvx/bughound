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

	host string       // host punycode (kindHostExact, kindURLPrefix ber-host nama)
	base string       // basis wildcard tanpa "*." (kindWildcard)
	port string       // port eksplisit, "" = semua port (kebijakan v1)
	path string       // prefix path ternormalkan (kindURLPrefix)
	addr netip.Addr   // kindIP, juga kindURLPrefix ber-host IP
	cidr netip.Prefix // kindCIDR
}

// parseEntry mengurai satu string scope menjadi entry, lalu menolak bentuk yang
// terurai tapi takkan pernah cocok target. Entri semacam itu berbahaya di
// out-of-scope: eksklusinya mati tanpa peringatan (under-blocking).
func parseEntry(raw string) (entry, error) {
	e, err := parseForm(raw)
	if err != nil {
		return entry{}, err
	}
	port, ok := canonicalPort(e.port)
	if !ok {
		return entry{}, fmt.Errorf("port tak valid: %q", raw)
	}
	e.port = port
	if isIPRange(e.host) {
		return entry{}, fmt.Errorf("rentang IP tak didukung, pakai CIDR: %q", raw)
	}
	return e, nil
}

// parseForm mengenali bentuk entri. Pencocokan dilakukan positif per-bentuk: apa
// pun yang tidak cocok bentuk yang didukung ditolak.
func parseForm(raw string) (entry, error) {
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
		nh, addr, err := canonicalHost(host)
		if err != nil {
			return entry{}, fmt.Errorf("%q: %w", raw, err)
		}
		p := normalizePath(s[i:])
		if addr.IsValid() {
			// IP + path tanpa skema ambigu: "203.0.113.0/33" dan "203.0.113.0/24:443"
			// adalah CIDR rusak, bukan path. Ditolak, bukan ditebak.
			if p != "/" {
				return entry{}, fmt.Errorf("IP ber-path wajib berskema, rentang wajib CIDR valid: %q", raw)
			}
			return entry{raw: raw, kind: kindIP, addr: addr, port: port}, nil
		}
		return entry{raw: raw, kind: kindURLPrefix, host: nh, port: port, path: p}, nil
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
	nh, addr, err := canonicalHost(host)
	if err != nil {
		return entry{}, fmt.Errorf("%q: %w", raw, err)
	}
	if addr.IsValid() {
		return entry{raw: raw, kind: kindIP, addr: addr, port: port}, nil
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
	nh, addr, err := canonicalHost(u.Hostname())
	if err != nil {
		return entry{}, fmt.Errorf("%q: %w", raw, err)
	}
	return entry{raw: raw, kind: kindURLPrefix, host: nh, addr: addr, port: u.Port(), path: normalizePath(u.Path)}, nil
}

// matches melaporkan apakah target t cocok dengan entri ini. Target hostname
// hanya cocok dengan entri berhost nama; target IP hanya cocok dengan entri
// berhost IP atau CIDR (tidak ada resolusi DNS di v1). onUnknownPort adalah hasil
// bila entri berport tapi port target tak diketahui.
func (e entry) matches(t normTarget, onUnknownPort bool) bool {
	switch e.kind {
	case kindIP:
		return t.isIP && t.addr == e.addr && portOK(e.port, t.effPort, onUnknownPort)
	case kindCIDR:
		return t.isIP && e.cidr.Contains(t.addr)
	case kindHostExact:
		return !t.isIP && t.host == e.host && portOK(e.port, t.effPort, onUnknownPort)
	case kindWildcard:
		return !t.isIP && isSubdomain(t.host, e.base)
	case kindURLPrefix:
		return e.sameHost(t) && portOK(e.port, t.effPort, onUnknownPort) && pathUnder(e.path, t.path)
	}
	return false
}

// sameHost membandingkan host entri URL dengan target: IP dengan IP, nama dengan
// nama. Bentuk sama tapi jenis beda tak pernah cocok.
func (e entry) sameHost(t normTarget) bool {
	if e.addr.IsValid() {
		return t.isIP && t.addr == e.addr
	}
	return !t.isIP && t.host == e.host
}

// portOK menerapkan kebijakan port v1: scope berbasis host mencakup semua port
// kecuali entri menyebut port eksplisit. targetPort adalah port efektif target;
// kosong berarti tak diketahui, dan hasilnya onUnknown.
func portOK(entryPort, targetPort string, onUnknown bool) bool {
	if entryPort == "" {
		return true
	}
	if targetPort == "" {
		return onUnknown
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
