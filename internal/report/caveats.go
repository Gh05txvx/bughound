package report

import (
	"net/url"
	"strings"

	"bughound/internal/finding"
)

// Caveat is a triage note on a report: a likely false positive, or a coverage
// gap worth a manual follow-up. Caveats are heuristics (hints), not verdicts:
// the hunter still verifies. They are computed locally from the findings, with
// NO external calls, so they are safe on a confidential engagement.
type Caveat struct {
	Kind   string // "fp" (likely false positive) or "coverage" (blind spot / seed hint)
	Title  string
	Detail string
}

// redirectTypes are the open-redirect type slugs across engines (kept in step
// with finding dedup's canonical family).
var redirectTypes = map[string]bool{
	"open-redirect": true, "open-redirect-bypass": true,
	"external-redirect": true, "off-site-redirect": true,
}

// Caveats returns triage hints for a report's findings. Deterministic and
// local-only (no network). An empty slice means nothing was flagged.
func Caveats(items []*finding.Finding) []Caveat {
	var out []Caveat
	seen := map[string]bool{}
	add := func(kind, key, title, detail string) {
		if seen[kind+"|"+key] {
			return
		}
		seen[kind+"|"+key] = true
		out = append(out, Caveat{Kind: kind, Title: title, Detail: detail})
	}

	// Endpoints that are open redirects: an XSS/traversal on the SAME path is
	// usually the scanner mislabelling the reflected redirect URL.
	redirectPaths := map[string]bool{}
	gated, plainHTTP := false, false
	for _, f := range items {
		if redirectTypes[strings.ToLower(f.Type)] {
			redirectPaths[pathOnly(f.Location.URL)] = true
		}
		if p := strings.ToLower(pathOnly(f.Location.URL)); strings.HasPrefix(p, "/account") || strings.HasPrefix(p, "/admin") {
			gated = true
		}
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(f.Target)), "http://") {
			plainHTTP = true
		}
	}

	for _, f := range items {
		typ := strings.ToLower(f.Type)
		path := pathOnly(f.Location.URL)

		// FP 1: XSS/traversal on an endpoint that is also an open redirect.
		if (strings.Contains(typ, "cross-site-scripting") || strings.Contains(typ, "xss") || strings.Contains(typ, "path-traversal")) && redirectPaths[path] {
			add("fp", "redirect-sink|"+path,
				"Likely FP: "+strings.ToUpper(string(f.Severity))+" "+f.Title+" on "+path,
				path+" is an open redirect; active scanners often mislabel the reflected URL as XSS or path traversal. Confirm the real impact (script execution / file read) independently before reporting.")
		}

		// FP 2: transport/cookie issues are moot on a plain-HTTP target.
		if plainHTTP && (hasCWE(f, "CWE-614") || strings.Contains(typ, "without-secure") || strings.Contains(typ, "samesite") || strings.Contains(typ, "strict-transport") || strings.Contains(typ, "hsts") || strings.Contains(typ, "http-only-site")) {
			add("fp", "http-tls",
				"Likely FP on plain HTTP: cookie-Secure / SameSite / HSTS",
				"The target is served over plain HTTP, so Secure-flag, SameSite, HSTS and SSL/TLS findings only matter once it is behind HTTPS. Treat them as hygiene, not vulnerabilities.")
		}

		// FP 3: ZAP's format-string check is noisy on web apps.
		if strings.Contains(typ, "format-string") {
			add("fp", "format-string",
				"Likely FP: Format String Error",
				"ZAP's format-string active check frequently false-positives on web apps that do not feed input to a C-style printf. Verify before reporting.")
		}

		// Coverage: a redirect to login marks content that needs a session + seed.
		if strings.Contains(strings.ToLower(f.Location.URL), "login?next=") {
			if nxt := nextTarget(f.Location.URL); nxt != "" {
				add("coverage", "authwall|"+nxt,
					"Coverage: auth wall toward "+nxt,
					"The scan was redirected to login when reaching "+nxt+". Provide an authenticated session (RoE) and also seed "+nxt+" as a target: the crawler stops at the login redirect and will not test behind it on its own.")
			}
		}
	}

	// Standing reminder when there is gated content: crawling alone misses depth.
	if gated {
		out = append(out, Caveat{
			Kind:  "coverage",
			Title: "Coverage: seed deep endpoints",
			Detail: "bughound tests the linked and discovered surface. Endpoints reachable only by interaction or prior knowledge (an existing record's detail page, admin tools, a file-download parameter) are not found by crawling and must be seeded explicitly, with an auth session where needed.",
		})
	}
	return out
}

// pathOnly returns the path part of a URL (no scheme/host/query), for grouping.
func pathOnly(raw string) string {
	if u, err := url.Parse(strings.TrimSpace(raw)); err == nil && u.Path != "" {
		return u.Path
	}
	if before, _, found := strings.Cut(raw, "?"); found {
		return before
	}
	return raw
}

// nextTarget pulls the ?next= value from a login-redirect URL.
func nextTarget(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		return u.Query().Get("next")
	}
	return ""
}

func hasCWE(f *finding.Finding, cwe string) bool {
	for _, c := range f.CWE {
		if strings.EqualFold(strings.TrimSpace(c), cwe) {
			return true
		}
	}
	return false
}
