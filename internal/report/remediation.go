package report

import (
	"strings"

	"bughound/internal/finding"
)

// remediationFor returns actionable remediation guidance for the draft report,
// chosen by the finding's CLASS (type/title/CWE, then the OWASP category as a
// fallback). The order of each entry: root-cause fix → defense in depth →
// detection (in line with the reporting methodology: specific, ordered
// remediation instead of a generic "validate input"). The content is purely
// defensive, with no exploitation steps; the hunter may edit it before the
// MANUAL submission (no auto-submit).
//
// Deterministic and offline: it calls no network or LLM, which suits a
// reproducible draft. It always returns at least one item.
func remediationFor(f *finding.Finding) []string {
	// Normalize hyphens→spaces so hyphenated types ("file-upload",
	// "os-command-injection") match keywords that contain spaces.
	hay := strings.ReplaceAll(strings.ToLower(f.Type+" "+f.Title), "-", " ")
	cwe := strings.ToUpper(strings.Join(f.CWE, " "))
	has := func(subs ...string) bool {
		for _, s := range subs {
			if strings.Contains(hay, s) {
				return true
			}
		}
		return false
	}
	hasCWE := func(ids ...string) bool {
		for _, id := range ids {
			if strings.Contains(cwe, id) {
				return true
			}
		}
		return false
	}

	switch {
	case has("sqli", "sql-injection", "sql injection", "nosql") || hasCWE("CWE-89", "CWE-943"):
		return []string{
			"Use prepared statements / parameterized queries (or a safe ORM); do not build queries from user input.",
			"Give the DB account least privilege and turn off dangerous primitives (xp_cmdshell, LOAD_FILE/INTO OUTFILE, COPY … PROGRAM) when they are not needed.",
			"Alert on anomalous patterns (UNION/SLEEP/comments) in the query log for early detection.",
		}
	case has("xss", "cross-site scripting", "cross site scripting") || hasCWE("CWE-79"):
		return []string{
			"Encode output for its context (HTML/attribute/JS/URL); prefer a framework with auto-escaping.",
			"Set a strict Content-Security-Policy (no unsafe-inline) as defense in depth, and sanitize rich text with an allowlist.",
			"Set session cookies HttpOnly+Secure+SameSite to limit the impact of session theft.",
		}
	case has("ssrf", "server-side request forgery") || hasCWE("CWE-918"):
		return []string{
			"Validate the destination URL against a host/scheme allowlist; reject private/link-local IPs (169.254.0.0/16, 10/8, 127/8) and cloud metadata endpoints.",
			"Fetch through a controlled egress proxy, turn off redirects you do not need, and pin DNS→IP to prevent rebinding.",
			"Log outbound destinations from server components to detect suspicious internal access.",
		}
	case has("ssti", "template injection") || hasCWE("CWE-1336"):
		return []string{
			"Do not build templates from user input; treat input as DATA (context variables), not as template source.",
			"Use a sandboxed / logic-less template engine and disable eval and access to dangerous attributes.",
		}
	case has("xxe", "xml external entity") || hasCWE("CWE-611"):
		return []string{
			"Disable external entity and DTD resolution in the XML parser (FEATURE_SECURE_PROCESSING / disallow-doctype-decl).",
			"Prefer a less complex format (JSON) where possible; validate the schema of accepted XML.",
		}
	case has("deserial") || hasCWE("CWE-502"):
		return []string{
			"Avoid native deserialization of untrusted data; use a plain data format (JSON) with a strict schema.",
			"If you must, apply a type/class allowlist and an integrity check (signature) on serialized objects.",
		}
	case has("command inject", "os command", "rce", "remote code execution") || hasCWE("CWE-77", "CWE-78"):
		return []string{
			"Do not call a shell with user input; use an API that takes an argument array (no shell) plus strict allowlist validation.",
			"Run the component with minimal privileges and isolation (container/seccomp) to limit the impact.",
			"Monitor for unusual child processes spawned by the web service.",
		}
	case has("idor", "bola", "broken access", "access control", "authorization", "privilege") || hasCWE("CWE-639", "CWE-284", "CWE-285", "CWE-862"):
		return []string{
			"Enforce object-level authorization on the server for EVERY request (compare the resource owner with the session identity); default deny.",
			"Use unguessable identifiers (UUIDs) to complement access control, not to replace it.",
			"Log failed cross-object/account access to detect enumeration.",
		}
	case has("open redirect", "open-redirect") || hasCWE("CWE-601"):
		return []string{
			"Validate the redirect destination against an allowlist of relative paths/hosts; reject absolute external URLs.",
			"If an external redirect is needed, show a confirmation interstitial.",
		}
	case has("file upload", "unrestricted upload", "arbitrary file") || hasCWE("CWE-434"):
		return []string{
			"Validate the real content type (magic bytes) plus an extension allowlist; use server-generated file names.",
			"Store uploads outside the webroot / on non-executable storage and serve them through a separate handler; turn off execution in the upload directory.",
		}
	case has("request smuggling", "smuggling") || hasCWE("CWE-444"):
		return []string{
			"Normalize Content-Length vs Transfer-Encoding parsing on every hop; reject requests with ambiguous length headers.",
			"Align the front end and back end (HTTP/2 end to end where possible) and turn off risky connection reuse.",
		}
	case has("parameter pollution", "hpp") || hasCWE("CWE-235"):
		return []string{
			"Canonicalize duplicate parameters explicitly (take the first or the last, consistently) across the stack.",
			"Validate the type and number of expected parameters; reject extras.",
		}
	case has("cors") || hasCWE("CWE-942"):
		return []string{
			"Use a strict origin allowlist; do not reflect arbitrary Origins and do not combine ACAO:* with credentials.",
			"Keep the allowed methods and headers to a minimum.",
		}
	case has("jwt", "json web token") || hasCWE("CWE-347"):
		return []string{
			"Verify the signature with a fixed algorithm on the server; REJECT alg \"none\" and algorithm switching (e.g. RS→HS).",
			"Use strong keys/secrets with rotation; validate the exp/aud/iss claims.",
		}
	case has("oauth", "openid", "sso"):
		return []string{
			"Validate redirect_uri against an exact-match allowlist; require and verify the state parameter (anti-CSRF) plus PKCE.",
			"Do not leak tokens through the URL/Referer; use a safe response_mode.",
		}
	case has("csrf", "cross-site request forgery") || hasCWE("CWE-352"):
		return []string{
			"Require a per-session anti-CSRF token on state-changing actions; set cookies SameSite=Lax/Strict.",
			"Verify Origin/Referer on sensitive requests as defense in depth.",
		}
	case has("exposed", "disclosure", "information leak", "info leak", "directory listing", "debug", "exposure") || hasCWE("CWE-200", "CWE-538"):
		return []string{
			"Remove or restrict access to sensitive paths and artifacts (.env, backups, .git, debug endpoints); return 404/403.",
			"Turn off debug mode/verbose errors in production and review headers that leak versions.",
		}
	}

	// Fallback per OWASP 2021 category (coarse but still actionable).
	switch f.OWASP {
	case finding.A01:
		return []string{"Enforce consistent server-side authorization for every action and object; default deny."}
	case finding.A02:
		return []string{"Use strong cryptography and TLS (avoid weak algorithms/static keys); protect sensitive data in transit and at rest."}
	case finding.A03:
		return []string{"Treat all input as untrusted: parameterize/escape for the interpreter's context (SQL/HTML/OS/template)."}
	case finding.A04:
		return []string{"Fix the design at its root: apply security controls in the business flow (rate limits, state validation, quota limits)."}
	case finding.A05:
		return []string{"Tighten the configuration: turn off unused features/endpoints, debug off, safe headers, safe defaults."}
	case finding.A06:
		return []string{"Update components/dependencies to versions without known vulnerabilities; watch advisories and maintain an SBOM."}
	case finding.A07:
		return []string{"Strengthen authentication and sessions: MFA, a credential policy, session invalidation, token protection."}
	case finding.A08:
		return []string{"Ensure data/code integrity: verify the signatures of updates/packages; avoid untrusted deserialization."}
	case finding.A09:
		return []string{"Add logging and monitoring for security events and make sure alerting works."}
	case finding.A10:
		return []string{"Restrict server-side requests with a destination allowlist; block internal ranges and metadata endpoints."}
	}

	return []string{"Fix the root cause on the server; validate and encode for the interpreter's context; add relevant logging/detection."}
}
