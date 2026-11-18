package ffuf

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// robots.txt enrichment. robots.txt advertises the paths a site owner wants
// hidden (Disallow/Allow), which makes them high-value probe candidates for a
// hunter (e.g. juice-shop: "Disallow: /ftp" -> an exposed directory). bughound
// fetches it through the SAME egress proxy as ffuf, so the robots.txt fetch is
// scope-enforced too; and every parsed path is still probed by ffuf through that
// proxy (a second layer). Best-effort: a failure or absence means no enrichment,
// not an error.

const (
	maxRobotsBytes = 256 * 1024       // cap on the robots.txt body read (avoid a huge body)
	maxRobotsPaths = 200              // cap on paths taken (avoid a bloated wordlist)
	robotsTimeout  = 10 * time.Second // timeout for the robots.txt fetch
)

// robotsPaths fetches & parses BASE/robots.txt through the egress proxy. Without
// a proxy (e.g. mock/test) there is NO fetch, so no connection to the target ever
// bypasses the scope guard.
func (r *Runner) robotsPaths(ctx context.Context, target string) []string {
	if r.proxyAddr == "" {
		return nil // no scope-enforcing proxy -> do not fetch (fail-safe)
	}
	base := baseOf(target)
	if base == "" {
		return nil
	}
	client, err := proxiedClient(r.proxyAddr, robotsTimeout)
	if err != nil {
		return nil
	}
	return robotsPathsFrom(ctx, client, base, r.authHeaders...)
}

// setHeaders attaches the auth headers "Name: value" (Lever 1) to the enrichment
// request, matching ffuf's -H probe: robots.txt/spec behind a login is only
// readable with a session. Set on the request (not the transport) so Go still
// drops Cookie/Authorization on a cross-domain redirect.
func setHeaders(req *http.Request, hdrs []string) {
	for _, h := range hdrs {
		if name, val, ok := strings.Cut(h, ":"); ok && strings.TrimSpace(name) != "" {
			req.Header.Set(strings.TrimSpace(name), strings.TrimSpace(val))
		}
	}
}

// proxiedClient builds an http.Client that routes EVERY request through the
// egress proxy (http.Transport.Proxy), so the scope guard evaluates each
// connection. Certificates are not verified, same as the engines: the proxy opens
// TLS for a host with a path-based exclusion, and a verifying client would fail silently there.
func proxiedClient(proxyAddr string, timeout time.Duration) (*http.Client, error) {
	pu, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}, nil
}

// robotsPathsFrom GETs base/robots.txt with the given client and parses the
// result. Split out so it can be tested without a proxy (a direct client).
func robotsPathsFrom(ctx context.Context, client *http.Client, base string, hdrs ...string) []string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/robots.txt", nil)
	if err != nil {
		return nil
	}
	setHeaders(req, hdrs)
	resp, err := client.Do(req)
	if err != nil {
		return nil // robots.txt missing/blocked by scope -> no enrichment
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxRobotsBytes))
	return parseRobotsPaths(body, maxRobotsPaths)
}

// parseRobotsPaths extracts literal paths from Disallow/Allow directives. Only
// relative paths ("/...") are accepted; wildcard patterns (*, $) and absolute
// URLs are dropped because they are not literal probe paths. Values are returned
// in FUZZ form (no edge slashes), deduped, and capped at max.
func parseRobotsPaths(body []byte, max int) []string {
	var out []string
	seen := map[string]bool{}
	for _, raw := range strings.Split(string(body), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(line[:colon])) {
		case "disallow", "allow":
		default:
			continue
		}
		val := strings.TrimSpace(line[colon+1:])
		if h := strings.IndexByte(val, '#'); h >= 0 { // inline comment
			val = strings.TrimSpace(val[:h])
		}
		val = strings.SplitN(val, "?", 2)[0] // drop the query
		if val == "" || val == "/" || !strings.HasPrefix(val, "/") {
			continue // empty / whole site / not a relative path
		}
		if strings.ContainsAny(val, "*$") {
			continue // wildcard pattern, not a literal path
		}
		val = strings.Trim(val, "/") // FUZZ form (no edge slashes)
		if val == "" || strings.ContainsAny(val, " \t") {
			continue
		}
		if seen[val] {
			continue
		}
		seen[val] = true
		out = append(out, val)
		if len(out) >= max {
			break
		}
	}
	return out
}

// mergeWordlist writes a new temp wordlist = base contents + the extra paths
// (deduped against base). The base (built-in or user wordlist) is NOT changed.
func mergeWordlist(basePath string, extra []string) (string, func(), error) {
	base, err := os.ReadFile(basePath)
	if err != nil {
		return "", nil, err
	}
	existing := map[string]bool{}
	for _, ln := range strings.Split(string(base), "\n") {
		if ln = strings.TrimSpace(ln); ln != "" {
			existing[ln] = true
		}
	}
	var buf bytes.Buffer
	buf.Write(base)
	if len(base) > 0 && base[len(base)-1] != '\n' {
		buf.WriteByte('\n')
	}
	for _, p := range extra {
		if existing[p] {
			continue
		}
		existing[p] = true
		buf.WriteString(p)
		buf.WriteByte('\n')
	}
	return tempWordlist("ffuf-wl-robots-*.txt", buf.Bytes())
}
