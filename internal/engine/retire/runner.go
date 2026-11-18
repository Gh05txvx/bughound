// Package retire is the retire.js engine adapter: it detects outdated/vulnerable
// client-side JavaScript libraries (CVE) on assets the target SERVES.
//
// retire.js is a file-based scanner (it does not crawl URLs), so this adapter:
// fetch the target HTML -> extract SAME-ORIGIN <script src> -> download each JS
// through the egress proxy (scope-enforced) to a temp dir -> run
// `retire --jspath` -> normalize the JSON output to the Uniform Finding Schema.
//
// Only SAME-ORIGIN JS (in-scope) is downloaded; a third-party CDN library is not
// fetched — it is outside the target's assets and would be blocked by the scope guard. Like the other
// engines, an outbound connection must go through the egress proxy (UseProxy is called by the orchestrator).
package retire

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"bughound/internal/finding"
)

// Runner is the REAL retire.js engine.
type Runner struct {
	Binary    string // default "retire"
	RateLimit int    // kept for factory consistency; few downloads, not clamped
	proxyAddr string
}

// Name satisfies engine.Engine.
func (r *Runner) Name() string { return "retire" }

// UseProxy satisfies engine.ProxyAware: connections (fetch HTML + download JS) are routed
// to the egress proxy so every connection enforces the scope guard.
func (r *Runner) UseProxy(addr string) { r.proxyAddr = addr }

const (
	maxJSFiles   = 40              // cap on JS files downloaded per target
	maxJSBytes   = 8 * 1024 * 1024 // size cap per JS file
	maxHTMLBytes = 4 * 1024 * 1024 // cap on reading the target HTML
	fetchTimeout = 20 * time.Second
)

// Scan satisfies engine.Engine.
func (r *Runner) Scan(ctx context.Context, target, program, runID string) ([]*finding.Finding, error) {
	// Fail-safe: without the egress proxy, make NO connection at all. Every engine
	// egress must go through the scope-enforced proxy (the orchestrator calls UseProxy
	// before Scan); an empty proxyAddr = misconfiguration -> no fetch, in line with the
	// principle "never trigger a connection that bypasses the scope guard".
	if r.proxyAddr == "" {
		return nil, nil
	}
	client, err := r.httpClient()
	if err != nil {
		return nil, fmt.Errorf("retire: client: %w", err)
	}
	html := fetchBody(ctx, client, target, maxHTMLBytes)
	if len(html) == 0 {
		return nil, nil // target unreachable/empty -> nothing to analyze
	}
	jsURLs := sameOriginScriptURLs(target, html)
	if len(jsURLs) == 0 {
		return nil, nil
	}

	dir, err := os.MkdirTemp("", "retire-js-*")
	if err != nil {
		return nil, fmt.Errorf("retire: temp dir: %w", err)
	}
	defer os.RemoveAll(dir)

	fileToURL := map[string]string{}
	n := 0
	for _, ju := range jsURLs {
		if n >= maxJSFiles {
			break
		}
		body := fetchBody(ctx, client, ju, maxJSBytes)
		if len(body) == 0 {
			continue
		}
		name := fmt.Sprintf("%03d.js", n)
		if werr := os.WriteFile(filepath.Join(dir, name), body, 0o600); werr != nil {
			continue
		}
		fileToURL[name] = ju
		n++
	}
	if n == 0 {
		return nil, nil
	}

	out, err := r.runRetire(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("retire: execution failed: %w", err)
	}
	return Parse(out, fileToURL, target, program, runID)
}

func (r *Runner) bin() string {
	if strings.TrimSpace(r.Binary) != "" {
		return r.Binary
	}
	return "retire"
}

// runRetire runs retire.js over a dir holding the downloaded JS files.
// --exitwith 0: finding a vulnerability must NOT make a non-zero exit (we read
// the JSON ourselves), so cmd.Run does not mistake it for an execution failure.
func (r *Runner) runRetire(ctx context.Context, dir string) ([]byte, error) {
	outFile := filepath.Join(dir, "retire-out.json")
	args := []string{"--jspath", dir, "--outputformat", "json", "--outputpath", outFile, "--exitwith", "0"}
	cmd := exec.CommandContext(ctx, r.bin(), args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w (%s)", err, strings.TrimSpace(stderr.String()))
	}
	return os.ReadFile(outFile)
}

// httpClient builds a client that routes requests through the egress proxy when present.
// The certificate is not verified, like the engines: the proxy opens TLS for a host that has
// a path-based exclusion, and a verifying client would fail silently there.
func (r *Runner) httpClient() (*http.Client, error) {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	if r.proxyAddr != "" {
		pu, err := url.Parse("http://" + r.proxyAddr)
		if err != nil {
			return nil, err
		}
		tr.Proxy = http.ProxyURL(pu)
	}
	return &http.Client{Timeout: fetchTimeout, Transport: tr}, nil
}

var scriptSrc = regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']([^"']+)["']`)

// sameOriginScriptURLs extracts <script src> URLs and keeps only the ones
// SAME-ORIGIN with the target (same host). A third-party CDN JS is not fetched — outside
// the target's assets & would be blocked by the scope guard.
func sameOriginScriptURLs(target string, html []byte) []string {
	base, err := url.Parse(target)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, m := range scriptSrc.FindAllSubmatch(html, -1) {
		raw := strings.TrimSpace(string(m[1]))
		if raw == "" {
			continue
		}
		u, err := base.Parse(raw) // resolve relative to the target
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			continue
		}
		if !strings.EqualFold(u.Host, base.Host) {
			continue // not same-origin
		}
		u.Fragment = ""
		s := u.String()
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// fetchBody GETs a URL and returns the (capped) body only when 200.
func fetchBody(ctx context.Context, client *http.Client, u string, limit int64) []byte {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, limit))
	return body
}
