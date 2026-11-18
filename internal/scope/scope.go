// Package scope implements the Scope Guard (BH-SPEC-SCOPE): the most
// critical security control in bughound. It answers one question for every
// target — may it be touched or not — with the most conservative stance.
//
// The principles this code enforces:
//   - Default deny: if not proven in-scope, reject.
//   - Out-of-scope wins: matching in-scope and out-of-scope at once => reject.
//   - Fail closed: a target/scope that fails to parse => reject, not allow.
//   - Deterministic: the same input always gives the same decision.
//   - One decision point: Evaluate is used at both the input and egress layer.
//
// This guard does no DNS resolution in v1 (see the open DNS rebinding question
// in BH-SPEC-SCOPE): a hostname target is matched as a hostname, an IP target
// is matched as an IP.
package scope

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

// Reason explains why a decision was made (for the audit trail).
type Reason string

const (
	ReasonInScope    Reason = "in-scope"
	ReasonOutOfScope Reason = "out-of-scope"
	ReasonNotInScope Reason = "not in-scope"
	ReasonParseError Reason = "parse error"
)

// Result is the guard's decision for one target. Its fields are enough to
// record to the audit trail per BH-SPEC-SCOPE (the normalized target, the reason,
// and the triggering scope entry when a denial is because of out-of-scope).
type Result struct {
	Allowed      bool
	Reason       Reason
	Target       string // normalized target (for the audit)
	MatchedEntry string // the triggering scope entry (allow/deny), empty on default deny
}

// Guard holds the compiled in-scope and out-of-scope entries.
type Guard struct {
	in  []entry
	out []entry
}

// New compiles two scope lists into a Guard. An entry that cannot be parsed is
// NOT silently ignored: it is returned as an error so the user is
// told (BH-SPEC-SCOPE: "rejected at input, the user is told").
//
// The caller MUST treat a non-empty errs as a blocker:
// do not run a scan with a half-parsed scope. An out-of-scope entry
// that fails to parse in particular means under-blocking.
func New(inScope, outScope []string) (g *Guard, errs []error) {
	g = &Guard{}
	for _, raw := range inScope {
		e, err := parseEntry(raw)
		if err != nil {
			errs = append(errs, fmt.Errorf("in-scope: %w", err))
			continue
		}
		g.in = append(g.in, e)
	}
	for _, raw := range outScope {
		e, err := parseEntry(raw)
		if err != nil {
			errs = append(errs, fmt.Errorf("out-of-scope: %w", err))
			continue
		}
		g.out = append(g.out, e)
	}
	return g, errs
}

// Evaluate makes the decision for one target. The order matters: out-of-scope
// is checked first so it always wins, then in-scope, then default deny.
// Normalization always runs first; if it fails, the result is reject (fail closed).
func (g *Guard) Evaluate(target string) Result {
	t, err := normalizeTarget(target)
	if err != nil {
		return Result{Allowed: false, Reason: ReasonParseError, Target: strings.TrimSpace(target)}
	}
	norm := t.String()

	// Unknown port (a target without a port and scheme): an exclusion wins in doubt,
	// while an allow needs evidence.
	for _, e := range g.out {
		if e.matches(t, true) {
			return Result{Allowed: false, Reason: ReasonOutOfScope, Target: norm, MatchedEntry: e.raw}
		}
	}
	for _, e := range g.in {
		if e.matches(t, false) {
			return Result{Allowed: true, Reason: ReasonInScope, Target: norm, MatchedEntry: e.raw}
		}
	}
	return Result{Allowed: false, Reason: ReasonNotInScope, Target: norm}
}

// PathScoped reports whether a target host:port has a path-based exclusion. The decision
// for such a target needs the path of each request, so egress must not
// forward it as a blind tunnel. In-scope entries need not be looked at: a CONNECT that
// passes already proves the in-scope root path, and that entry covers the whole path.
// An unparsed target is answered true: in doubt means open, not a blind tunnel.
func (g *Guard) PathScoped(target string) bool {
	t, err := normalizeTarget(target)
	if err != nil {
		return true
	}
	for _, e := range g.out {
		if e.kind == kindURLPrefix && e.path != "/" && e.sameHost(t) && portOK(e.port, t.effPort, true) {
			return true
		}
	}
	return false
}

// normTarget is a target normalized to canonical form.
type normTarget struct {
	isIP bool
	addr netip.Addr // when isIP
	host string     // lowercase punycode host, when !isIP
	port string     // "" when not stated
	path string     // normalized path, "/" when absent

	effPort string // port, or the scheme default when not stated; "" when unknown
}

func (t normTarget) String() string {
	h := t.host
	if t.isIP {
		h = t.addr.String()
	}
	if t.port != "" {
		h = net.JoinHostPort(h, t.port)
	}
	if t.path != "" && t.path != "/" {
		h += t.path
	}
	return h
}

// normalizeTarget parses a target (with or without a scheme) into canonical
// form. Userinfo (user:pass@) is dropped; an IDN host is converted to punycode; an IP
// is parsed numerically.
func normalizeTarget(target string) (normTarget, error) {
	s := strings.TrimSpace(target)
	if s == "" {
		return normTarget{}, errors.New("empty target")
	}
	if hasSuspiciousChars(s) {
		return normTarget{}, fmt.Errorf("target contains forbidden characters (backslash/space/control): %q", target)
	}
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil || u.Host == "" {
			return normTarget{}, fmt.Errorf("invalid target URL: %q", target)
		}
		return finishTarget(u.Hostname(), u.Port(), u.Path, schemePort(u.Scheme))
	}
	hostport, p := s, ""
	if i := strings.IndexByte(s, '/'); i >= 0 {
		hostport, p = s[:i], s[i:]
	}
	if at := strings.LastIndexByte(hostport, '@'); at >= 0 {
		hostport = hostport[at+1:] // drop userinfo
	}
	host, port, err := splitHostPort(hostport)
	if err != nil {
		return normTarget{}, err
	}
	return finishTarget(host, port, p, "")
}

func finishTarget(host, rawPort, rawPath, defaultPort string) (normTarget, error) {
	port, ok := canonicalPort(rawPort)
	if !ok {
		return normTarget{}, fmt.Errorf("invalid target port: %q", rawPort)
	}
	h, addr, err := canonicalHost(host)
	if err != nil {
		return normTarget{}, err
	}
	// An IP target must be literal. A disguised form ("203.0.113.10.") is still resolved
	// through DNS by the engine, so the destination is not the proven IP judged here.
	if addr.IsValid() {
		if _, err := netip.ParseAddr(host); err != nil {
			return normTarget{}, fmt.Errorf("disguised target IP: %q", host)
		}
	}
	eff := port
	if eff == "" {
		eff = defaultPort
	}
	return normTarget{isIP: addr.IsValid(), addr: addr, host: h, port: port, effPort: eff, path: normalizePath(rawPath)}, nil
}

// schemePort returns the default port of a web scheme; "" when unknown.
func schemePort(scheme string) string {
	switch scheme {
	case "http", "ws":
		return "80"
	case "https", "wss":
		return "443"
	}
	return ""
}

// canonicalPort validates a port and writes it without leading zeros, so "0443"
// does not slip past a port-443 exclusion. Empty means not stated.
func canonicalPort(p string) (string, bool) {
	if p == "" {
		return "", true
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return "", false
	}
	return strconv.Itoa(n), true
}

// canonicalHost normalizes a host into a name or IP, exactly one filled.
// The IP is checked again after normalization: "203.0.113.10." and fullwidth digits look
// like a name but point to the same IP, and an IP entry does not match a name.
func canonicalHost(raw string) (string, netip.Addr, error) {
	if addr, err := netip.ParseAddr(raw); err == nil {
		return "", addr, nil
	}
	h, err := normalizeHost(raw)
	if err != nil {
		return "", netip.Addr{}, err
	}
	if addr, err := netip.ParseAddr(h); err == nil {
		return "", addr, nil
	}
	return h, netip.Addr{}, nil
}

// isIPRange recognizes range notation ("10.0.0.1-50", "10.0.0.1-10.0.0.50"). It is
// a valid DNS name, but the intent is a range and it will not match any IP.
func isIPRange(host string) bool {
	first, rest, found := strings.Cut(host, "-")
	if !found {
		return false
	}
	if _, err := netip.ParseAddr(first); err != nil {
		return false
	}
	if _, err := strconv.Atoi(rest); err == nil {
		return true
	}
	_, err := netip.ParseAddr(rest)
	return err == nil
}

// normalizeHost lowers a host to canonical form: lowercase, no trailing
// dot, and converted to punycode (xn--). This punycode conversion is what
// closes the homoglyph/IDN bypass: a Cyrillic host "аcme.io" becomes a different
// punycode label that will not match "acme.io", or is rejected by idna. Both
// fail closed.
func normalizeHost(h string) (string, error) {
	h = strings.TrimSuffix(strings.TrimSpace(h), ".")
	if h == "" {
		return "", errors.New("empty host")
	}
	ascii, err := idna.Lookup.ToASCII(h)
	if err != nil {
		return "", fmt.Errorf("normalizing host %q: %w", h, err)
	}
	// An empty label (".acme.io") passes idna, but will never match a target.
	if strings.HasPrefix(ascii, ".") || strings.HasSuffix(ascii, ".") || strings.Contains(ascii, "..") {
		return "", fmt.Errorf("host %q has an empty label", h)
	}
	return strings.ToLower(ascii), nil
}

// normalizePath normalizes a path: always absolute, resolving "."/".." and double
// slashes, dropping a trailing slash (except root). url.Parse already
// does safe percent-decoding for a path from a URL.
func normalizePath(p string) string {
	if p == "" || p == "/" {
		return "/"
	}
	return path.Clean("/" + strings.TrimLeft(p, "/"))
}

// hasSuspiciousChars reports whether s holds characters that can make
// different parsers read the authority differently (backslash, space, control, DEL).
// A valid scope hostname/URL never holds these characters (BH-F04).
func hasSuspiciousChars(s string) bool {
	for _, r := range s {
		if r == '\\' || r <= 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// splitHostPort separates host and port in an IPv6-aware way. An IP without a port
// (including IPv6 without brackets) is returned as-is; IPv6 with a port must
// use bracket notation "[::1]:8080".
func splitHostPort(s string) (host, port string, err error) {
	if s == "" {
		return "", "", errors.New("empty host")
	}
	if strings.HasPrefix(s, "[") {
		return net.SplitHostPort(s)
	}
	if _, e := netip.ParseAddr(s); e == nil {
		return s, "", nil // raw IP (v4 or v6 without brackets/port)
	}
	if strings.Count(s, ":") == 1 {
		return net.SplitHostPort(s)
	}
	if strings.Contains(s, ":") {
		return "", "", fmt.Errorf("ambiguous host:port: %q", s)
	}
	return s, "", nil
}
