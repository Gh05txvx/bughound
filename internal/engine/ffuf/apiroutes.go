package ffuf

import (
	"os"
	"strings"
)

// API route enrichment. Beyond a common directory wordlist, many high-value
// findings live on API endpoints that are unlinked or undocumented (e.g.
// /api/v1/..., /rest/..., /graphql). Assetnote publishes "apiroutes", a list of
// real API paths most often seen on the web (ordered by frequency), a good
// dictionary for brute-forcing API paths. bughound bundles it at build time
// (see Dockerfile) and feeds it to the already-proxied ffuf engine, so every
// API path probe is enforced by the scope guard too (same as the built-in
// wordlist, robots, and spec).
//
// Opt-in: active only when APIRoutes is set (per scan from the form, or a
// program preset). The volume is large (~thousands of paths), so it is off by default.

const (
	// defaultAPIWordlist is where the bundled API route wordlist sits in the image.
	// Override it with BUGHOUND_API_WORDLIST (power user: point at your own wordlist).
	defaultAPIWordlist = "/usr/local/share/bughound/wordlists/apiroutes.txt"
	// maxAPIRoutePaths caps how many paths are read (a guard rail in case the env
	// points at a huge file). The bundled list is already trimmed smaller than this.
	maxAPIRoutePaths = 20000
)

// apiRoutePaths returns the bundled API route paths in FUZZ form (no edge
// slashes) to merge into the ffuf wordlist. Active only when APIRoutes=true.
//
// Security: gated on proxyAddr (like robotsPaths/specPaths). Reading this file
// is purely local (no network), but amplifying to ~thousands of paths may only
// happen through the scope-enforced egress proxy. Without a proxy there is no
// enrichment, so no API path brute-forcing ever bypasses the scope guard.
// A missing bundle (e.g. local dev without the image) returns nil (best-effort, not an error).
func (r *Runner) apiRoutePaths() []string {
	if !r.APIRoutes || r.proxyAddr == "" {
		return nil
	}
	path := strings.TrimSpace(os.Getenv("BUGHOUND_API_WORDLIST"))
	if path == "" {
		path = defaultAPIWordlist
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil // bundle/file missing, no enrichment (not an error)
	}
	return normalizeAPIRoutes(data, maxAPIRoutePaths)
}

// normalizeAPIRoutes turns the API route wordlist into FUZZ-form paths: one path
// per line, edge slashes dropped (buildArgs assembles target + "/" + FUZZ),
// query dropped, blank/comment/wildcard/whitespace lines skipped, deduped,
// capped at max. Handles both the raw Assetnote file (paths with a leading
// slash) and one already normalized at build time.
func normalizeAPIRoutes(data []byte, max int) []string {
	var out []string
	seen := map[string]bool{}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.SplitN(line, "?", 2)[0] // drop the query
		line = strings.Trim(line, "/")         // FUZZ form (no edge slashes)
		if line == "" || strings.ContainsAny(line, " \t") || strings.ContainsAny(line, "*$") {
			continue // blank / whitespace / wildcard pattern, not a literal probe path
		}
		if seen[line] {
			continue
		}
		seen[line] = true
		out = append(out, line)
		if len(out) >= max {
			break
		}
	}
	return out
}
