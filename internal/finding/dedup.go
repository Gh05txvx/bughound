package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/url"
	"strings"
)

// ComputeDedupKey computes the deterministic dedup_key from BH-SPEC-FINDING:
//
//	sha256( lower(type) | host(target) | path(location.url) | METHOD | (parameter|"") )
//
// METHOD (GET/POST/...) is part of the identity so two different issues on the
// same path+parameter but different methods (e.g. GET vs POST) are not merged
// by mistake. The method is normalized to upper case; an empty one (engines
// that do not report it, e.g. ffuf/retire/SAST) stays empty, so behaviour for
// those engines is unchanged.
//
// Deliberately NOT part of the key: run_id, source_engine, timestamp, payload
// and query values. That way the same issue on the same parameter+method stays
// one finding even when two engines find it, or it is found in two runs.
//
// Exception: for SITE-WIDE types (see siteWide) the path AND the method are
// left out of the key (identity = origin). Engines (e.g. ZAP) report
// origin-level issues such as a missing CSP/HSTS header or permissive CORS once
// per crawled URL, although one origin = one misconfiguration. Ignoring path
// and method collapses every instance into one main finding; the store marks
// the rest as duplicates (hidden from counts and reports, still stored in full
// for audit).
func ComputeDedupKey(typ, target, locationURL, method, parameter string) string {
	typ = canonType(typ)
	path := pathOf(locationURL)
	meth := normMethod(method)
	if siteWide(typ) {
		path = "" // identity = origin, not path
		meth = "" // an origin-level issue is not specific to a method
	}
	if typ == typeOpenRedirect {
		// One open redirect per path. Engines name it differently and disagree on
		// the parameter/method (ZAP reports the redirect param, nuclei omits it),
		// so the same redirect shows up several times. Key by path only.
		// shortcut: two distinct redirect params on one path collapse into one;
		// fine until a target actually has multiple redirect sinks on one path.
		parameter = ""
		meth = ""
	}
	raw := strings.ToLower(strings.TrimSpace(typ)) + "|" +
		hostOf(target) + "|" +
		path + "|" +
		meth + "|" +
		parameter
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// normMethod normalizes an HTTP method to upper case with no surrounding
// spaces (e.g. "get" -> "GET"); an empty string stays empty. It keeps the key
// consistent when engines report different casing.
func normMethod(m string) string {
	return strings.ToUpper(strings.TrimSpace(m))
}

const typeOpenRedirect = "open-redirect"

// redirectSynonyms are the engine-specific slugs for one issue: ZAP emits
// "external-redirect"/"off-site-redirect", nuclei emits
// "open-redirect"/"open-redirect-bypass". canonType folds them together so a
// single open redirect is not reported several times.
var redirectSynonyms = map[string]bool{
	"open-redirect":        true,
	"open-redirect-bypass": true,
	"external-redirect":    true,
	"off-site-redirect":    true,
}

// canonType folds known cross-engine synonyms to one canonical type for dedup.
// Only the open-redirect family is folded today; any other type is returned
// normalized (lower, trimmed) but otherwise unchanged, so its key is identical
// to before.
func canonType(typ string) string {
	t := strings.ToLower(strings.TrimSpace(typ))
	if redirectSynonyms[t] {
		return typeOpenRedirect
	}
	return t
}

// siteWideTypes: issue types whose identity is the ORIGIN (host), not a
// specific path. It is an explicit list plus a conservative suffix pattern on
// purpose, so legitimate per-path findings (exposed-path, suspicious-comments
// per file, etc.) are NEVER collapsed by mistake.
var siteWideTypes = map[string]bool{
	"cross-domain-misconfiguration": true, // permissive CORS (origin-level)
	"modern-web-application":        true, // ZAP info, the same for the whole site
	"user-agent-fuzzer":             true, // header probe, not a specific path
}

// siteWide reports whether typ is an origin-level issue whose dedup must ignore
// the path. ZAP's header-policy family ("...-header-not-set" /
// "...-header-missing", e.g. CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
// is always origin-level, and so is technology leakage through X-Powered-By.
func siteWide(typ string) bool {
	t := strings.ToLower(strings.TrimSpace(typ))
	if siteWideTypes[t] {
		return true
	}
	return strings.HasSuffix(t, "-header-not-set") ||
		strings.HasSuffix(t, "-header-missing") ||
		strings.Contains(t, "x-powered-by")
}

// hostOf takes the host from target without scheme, userinfo or port. It is
// lowercased and has no trailing dot. Dedup v1 deliberately ignores the port
// (see the open question on refining dedup_key in BH-SPEC-FINDING).
func hostOf(target string) string {
	t := strings.ToLower(strings.TrimSpace(target))
	if t == "" {
		return ""
	}
	p := t
	if !strings.Contains(p, "://") {
		p = "//" + p // hint to url.Parse that this is an authority, not a path
	}
	if u, err := url.Parse(p); err == nil && u.Hostname() != "" {
		return strings.TrimSuffix(u.Hostname(), ".")
	}
	// Rough fallback when url.Parse fails.
	h := strings.TrimPrefix(t, "//")
	if i := strings.IndexByte(h, '/'); i >= 0 {
		h = h[:i]
	}
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	}
	return strings.TrimSuffix(h, ".")
}

// pathOf takes the path from a URL without the query string. Query values
// change between scans, so they must not be part of a finding's identity.
func pathOf(rawURL string) string {
	r := strings.TrimSpace(rawURL)
	if r == "" {
		return ""
	}
	if u, err := url.Parse(r); err == nil {
		return u.Path
	}
	if i := strings.IndexByte(r, '?'); i >= 0 {
		return r[:i]
	}
	return r
}
