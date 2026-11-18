package scope

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

// entryKind is a scope entry form supported in v1. Other forms (e.g. a free
// regex) are not supported and are rejected at parse time, not guessed at.
type entryKind int

const (
	kindHostExact entryKind = iota // app.acme.io
	kindWildcard                   // *.acme.io
	kindURLPrefix                  // https://acme.io/api/  or acme.io/api
	kindIP                         // 203.0.113.10
	kindCIDR                       // 203.0.113.0/24
)

// entry is one normalized scope rule.
type entry struct {
	raw  string
	kind entryKind

	host string       // punycode host (kindHostExact, kindURLPrefix with a name host)
	base string       // wildcard base without "*." (kindWildcard)
	port string       // explicit port, "" = all ports (v1 policy)
	path string       // normalized path prefix (kindURLPrefix)
	addr netip.Addr   // kindIP, also kindURLPrefix with an IP host
	cidr netip.Prefix // kindCIDR
}

// parseEntry parses one scope string into an entry, then rejects a form that
// parses but will never match a target. Such an entry is dangerous in
// out-of-scope: its exclusion dies without warning (under-blocking).
func parseEntry(raw string) (entry, error) {
	e, err := parseForm(raw)
	if err != nil {
		return entry{}, err
	}
	port, ok := canonicalPort(e.port)
	if !ok {
		return entry{}, fmt.Errorf("invalid port: %q", raw)
	}
	e.port = port
	if isIPRange(e.host) {
		return entry{}, fmt.Errorf("IP range not supported, use CIDR: %q", raw)
	}
	return e, nil
}

// parseForm recognizes the entry form. Matching is positive per form: anything
// that does not fit a supported form is rejected.
func parseForm(raw string) (entry, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return entry{}, errors.New("empty entry")
	}
	if hasSuspiciousChars(s) {
		return entry{}, fmt.Errorf("scope entry contains forbidden characters (backslash/space/control): %q", raw)
	}

	// 1. Subdomain wildcard: only in the leftmost position.
	if strings.HasPrefix(s, "*.") {
		base := strings.TrimPrefix(s, "*.")
		if base == "" || strings.Contains(base, "*") {
			return entry{}, fmt.Errorf("wildcard only in the leftmost subdomain: %q", raw)
		}
		nb, err := normalizeHost(base)
		if err != nil {
			return entry{}, fmt.Errorf("%q: %w", raw, err)
		}
		return entry{raw: raw, kind: kindWildcard, base: nb}, nil
	}
	if strings.Contains(s, "*") {
		return entry{}, fmt.Errorf("unsupported wildcard form (only *.domain): %q", raw)
	}

	// 2. URL / path prefix with a scheme.
	if strings.Contains(s, "://") {
		return parseURLEntry(raw, s)
	}

	// 3. CIDR.
	if p, err := netip.ParsePrefix(s); err == nil {
		return entry{raw: raw, kind: kindCIDR, cidr: p.Masked()}, nil
	}

	// 4. host/path without a scheme (contains "/").
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
			// An IP + path without a scheme is ambiguous: "203.0.113.0/33" and "203.0.113.0/24:443"
			// are broken CIDR, not a path. Rejected, not guessed.
			if p != "/" {
				return entry{}, fmt.Errorf("an IP with a path must have a scheme, a range must be valid CIDR: %q", raw)
			}
			return entry{raw: raw, kind: kindIP, addr: addr, port: port}, nil
		}
		return entry{raw: raw, kind: kindURLPrefix, host: nh, port: port, path: p}, nil
	}

	// 5. Raw IP.
	if addr, err := netip.ParseAddr(s); err == nil {
		return entry{raw: raw, kind: kindIP, addr: addr}, nil
	}

	// 6. host[:port] or ip:port.
	host, port, err := splitHostPort(s)
	if err != nil {
		return entry{}, fmt.Errorf("unrecognized scope entry: %q", raw)
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
		return entry{}, fmt.Errorf("invalid scope URL %q: %w", raw, err)
	}
	if u.Host == "" {
		return entry{}, fmt.Errorf("scope URL without a host: %q", raw)
	}
	nh, addr, err := canonicalHost(u.Hostname())
	if err != nil {
		return entry{}, fmt.Errorf("%q: %w", raw, err)
	}
	return entry{raw: raw, kind: kindURLPrefix, host: nh, addr: addr, port: u.Port(), path: normalizePath(u.Path)}, nil
}

// matches reports whether target t matches this entry. A hostname target
// matches only a name-host entry; an IP target matches only an IP-host or CIDR
// entry (no DNS resolution in v1). onUnknownPort is the result when the entry
// has a port but the target port is unknown.
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

// sameHost compares a URL entry's host with the target: IP with IP, name with
// name. The same form but a different kind never matches.
func (e entry) sameHost(t normTarget) bool {
	if e.addr.IsValid() {
		return t.isIP && t.addr == e.addr
	}
	return !t.isIP && t.host == e.host
}

// portOK applies the v1 port policy: a host-based scope covers all ports
// unless the entry names an explicit port. targetPort is the target's effective port;
// empty means unknown, and the result is onUnknown.
func portOK(entryPort, targetPort string, onUnknown bool) bool {
	if entryPort == "" {
		return true
	}
	if targetPort == "" {
		return onUnknown
	}
	return entryPort == targetPort
}

// isSubdomain reports whether host is a true subdomain of base. The apex
// (host == base) is deliberately NOT covered by a wildcard (BH-SPEC-SCOPE). Comparing
// on the label boundary keeps "acme.io.evil.com" from matching base "acme.io".
func isSubdomain(host, base string) bool {
	if host == base {
		return false
	}
	return strings.HasSuffix(host, "."+base)
}

// pathUnder reports whether the target path is under the prefix on a segment
// boundary (not just a string prefix): prefix "/api" covers "/api" and
// "/api/v1", but not "/apixyz".
func pathUnder(prefix, target string) bool {
	if prefix == "" || prefix == "/" {
		return true
	}
	return target == prefix || strings.HasPrefix(target, prefix+"/")
}
