// Package engine defines the scan engine contract. A real implementation
// runs an engine binary (nuclei, ZAP, etc.) as a subprocess; a mock
// implementation returns recorded results with no network (used in M0 & E2E).
//
// Only an engine (worker) may reach a target, and only an in-scope target
// (BH-SPEC-SCOPE). The orchestrator enforces the scope guard before calling Scan
// and re-checks every finding that comes out.
package engine

import (
	"context"
	"regexp"

	"bughound/internal/finding"
)

// logoutWord: a logout route (logout, log-out, log_out, logoff, signout, sign-out,
// signoff, ...). When a scan carries auth headers (AuthAware), the crawler & engines
// AVOID it: one GET to a logout route kills the server-side session and the rest of the
// scan runs silently without login (proven live 2026-11-16: katana, nuclei,
// ffuf, ZAP).
const logoutWord = `(log|sign)[-_]?(out|off)`

// LogoutPattern matches an ABSOLUTE URL whose path/query is a logout route; the host
// is skipped (catalogoutlet.com is not logout). Valid for Go/katana regex (-cos)
// and Java/ZAP excludePaths (full match — hence the `.*` at the end).
const LogoutPattern = `(?i)^[a-z][a-z0-9+.-]*://[^/?#]*[/?#].*` + logoutWord + `.*`

var (
	logoutURLRE  = regexp.MustCompile(LogoutPattern)
	logoutPathRE = regexp.MustCompile(`(?i)` + logoutWord)
)

// IsLogoutURL: an absolute URL whose path/query is a logout route. A bare host /
// host:port (without a scheme) is never considered logout.
func IsLogoutURL(u string) bool { return logoutURLRE.MatchString(u) }

// IsLogoutPath: a path or wordlist entry (without scheme/host) that holds a logout route.
func IsLogoutPath(p string) bool { return logoutPathRE.MatchString(p) }

// Engine runs one engine against one target and returns findings
// already normalized to the Uniform Finding Schema (BH-SPEC-FINDING).
type Engine interface {
	Name() string
	Scan(ctx context.Context, target, program, runID string) ([]*finding.Finding, error)
}

// ProxyAware marks an engine whose connections can be routed through bughound's
// egress proxy (internal/egress). The orchestrator calls UseProxy before
// Scan so an external engine enforces the scope guard on every outbound connection
// (not just a check after the result). A mock engine does not need this.
type ProxyAware interface {
	UseProxy(addr string)
}

// OpenAPIAware marks an engine that can fuzz from an OpenAPI/Swagger
// spec (generating a complete request including the BODY, not just a
// query on a crawled URL). The orchestrator calls UseOpenAPISpec before Scan
// when the request carries a spec. The generated request STILL goes through the egress proxy
// (the scope guard enforces every connection; the spec does not bypass the boundary).
type OpenAPIAware interface {
	UseOpenAPISpec(spec []byte)
}

// AuthAware marks an engine that can include authentication headers
// (e.g. Cookie / Authorization) on every request, so a scan reaches
// content behind a login (Lever 1: authenticated scanning). The orchestrator calls
// UseAuthHeaders before Scan when the request carries session credentials. Each element
// has the form "Name: value" (ready to pass as `-H` to the tool).
//
// SECURITY: the headers only ride a request that has ALREADY passed the scope guard. If
// an engine follows a redirect to an out-of-scope host, egress refuses the dial before
// the connection so the credentials never leave the scope. A header value is a
// secret: never print it to a log/finding/report — the orchestrator redacts
// its value from evidence before saving (see Evidence.RedactHeaders).
type AuthAware interface {
	UseAuthHeaders(headers []string)
}
