package ffuf

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"

	"bughound/internal/openapi"
)

// OpenAPI/Swagger enrichment. Many APIs publish a spec at a well-known location
// (or embed it in swagger-ui-init.js). Documented endpoints are high-value probe
// candidates. bughound fetches the spec through the SAME scope-enforced egress
// proxy as ffuf, parses it with the internal/openapi package, then merges the
// endpoint PATHs into the wordlist (probed by ffuf into exposed-path findings).
// Best-effort: no spec or a failed parse means no enrichment, not an error.

// Well-known spec locations (standalone JSON/YAML) plus swagger-ui-init.js (JS-embedded).
var specLocations = []string{
	"/openapi.json",
	"/swagger.json",
	"/v3/api-docs",
	"/v2/api-docs",
	"/api-docs.json",
	"/swagger/v1/swagger.json",
	"/api-docs/swagger-ui-init.js", // swagger-ui embeds "swaggerDoc": {...}
}

const maxSpecPaths = 300 // cap on endpoints taken from the spec

// specPaths fetches the spec from well-known locations through the egress proxy
// and returns the endpoint PATHs (FUZZ form). Without a proxy it returns nil
// (fail-safe: no connection to the target ever bypasses the scope guard).
func (r *Runner) specPaths(ctx context.Context, target string) []string {
	if r.proxyAddr == "" {
		return nil
	}
	base := baseOf(target)
	if base == "" {
		return nil
	}
	client, err := proxiedClient(r.proxyAddr, robotsTimeout)
	if err != nil {
		return nil
	}
	return specPathsFrom(ctx, client, base, r.authHeaders...)
}

// specPathsFrom tries each well-known location with the given client and returns
// the paths from the first valid spec. Split out so it can be tested without a
// proxy (the client talks straight to the test server).
func specPathsFrom(ctx context.Context, client *http.Client, base string, hdrs ...string) []string {
	base = strings.TrimRight(base, "/")
	for _, loc := range specLocations {
		body := fetchBody(ctx, client, base+loc, hdrs)
		if len(body) == 0 {
			continue
		}
		if strings.HasSuffix(loc, ".js") {
			body = extractSwaggerDoc(body) // pull the swaggerDoc object out of the swagger-ui JS
		}
		if !looksLikeSpec(body) {
			continue // avoid parsing a catch-all SPA's HTML as a spec
		}
		eps, err := openapi.Endpoints(body, base)
		if err != nil {
			continue
		}
		if paths := endpointPaths(eps); len(paths) > 0 {
			return paths
		}
	}
	return nil
}

// fetchBody GETs a URL and returns the (capped) body only on a 200.
func fetchBody(ctx context.Context, client *http.Client, u string, hdrs []string) []byte {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	setHeaders(req, hdrs)
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4*maxRobotsBytes)) // a spec can be larger than robots
	return body
}

// looksLikeSpec: a quick sniff so a catch-all SPA's HTML is not fed to the parser.
// Every OpenAPI/Swagger spec has a "paths" object.
func looksLikeSpec(body []byte) bool {
	s := strings.TrimSpace(string(body))
	if s == "" || strings.HasPrefix(s, "<") {
		return false // empty or HTML
	}
	return strings.Contains(s, "\"paths\"") || strings.Contains(s, "paths:")
}

// extractSwaggerDoc extracts the JSON object after "swaggerDoc": from the body
// of swagger-ui-init.js (balanced-brace counting, ignoring braces inside strings).
// Empty when not found.
func extractSwaggerDoc(js []byte) []byte {
	s := string(js)
	i := strings.Index(s, "\"swaggerDoc\"")
	if i < 0 {
		return nil
	}
	j := strings.IndexByte(s[i:], '{')
	if j < 0 {
		return nil
	}
	start := i + j
	depth, inStr, esc := 0, false, false
	for k := start; k < len(s); k++ {
		c := s[k]
		if inStr {
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return []byte(s[start : k+1])
			}
		}
	}
	return nil
}

// endpointPaths turns absolute endpoint URLs (from openapi.Endpoints) into
// FUZZ-form PATHs (no edge slashes). The host is ignored; the path is still
// probed against the scan target and enforced by the scope guard at probe time.
// Deduped and capped.
func endpointPaths(urls []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, u := range urls {
		pu, err := url.Parse(u)
		if err != nil {
			continue
		}
		p := strings.Trim(pu.Path, "/")
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
		if len(out) >= maxSpecPaths {
			break
		}
	}
	return out
}
