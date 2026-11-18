package nuclei

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"bughound/internal/egress"
	"bughound/internal/engine"
	"bughound/internal/finding"
)

// DASTRunner is the ACTIVE DAST engine built on nuclei fuzzing (-dast): it SENDS
// payloads (SQLi/XSS/SSTI/etc.) to parameters found on the target, not just
// matching passive patterns. Because it is aggressive, run it ONLY against a
// legitimate target (a lab, in-scope, or with explicit permission), never
// casually in dev/test (see CLAUDE.md).
//
// Flow: crawl the target with katana (through the egress proxy), collect
// same-host URLs (parameterized ones prioritized as fuzz points), run
// `nuclei -dast -list` over those URLs (through the SAME egress proxy), normalize
// through Parse (nuclei DAST JSONL output is the same format as passive nuclei,
// so the parser does not change).
//
// When given an OpenAPI/Swagger spec (UseOpenAPISpec), the run also makes a
// `nuclei -dast -input-mode openapi/swagger` pass ONCE over that spec: it
// generates complete requests including the BODY (e.g. POST/PUT JSON), not just
// the query, which are injection points the URL crawl misses. This pass still
// goes through the same egress proxy and its findings are merged in.
//
// Security (sensitive area): EVERY request (crawl + fuzz) goes through the
// scope-enforced egress proxy; each request is checked by the scope guard before
// it opens (a payload changes a parameter's VALUE, the host stays in-scope;
// OAST/blind to a third party is blocked by the proxy). Volume is capped: the
// orchestrator rate limiter + nuclei `-rate-limit` + `-fuzz-aggression low` + a
// URL cap. Fail-safe: no proxy means no connection.
//
// Safety profile (Safety): non-destructive is ALWAYS on (no DoS payloads, no
// blind/OAST callbacks, see safety.go) so the scan looks for candidate bugs
// without breaking or changing the target's configuration; stealth mode
// (optional) makes crawl+fuzz low-and-slow for a minimal footprint on a target with a SOC.
type DASTRunner struct {
	Binary     string // default "nuclei"
	Katana     string // default "katana"
	RateLimit  int    // -rate-limit (req/s) for crawl & fuzz
	Aggression string // -fuzz-aggression (low|medium|high); default "low"
	Safety     Safety // safety profile: non-destructive (always) + stealth (optional)
	proxyAddr  string

	authHeaders []string // Lever 1: auth headers injected via -H into crawl & fuzz

	specBytes []byte // OpenAPI/Swagger spec (optional) for body fuzzing, see UseOpenAPISpec
	specDone  bool   // marker: the OpenAPI pass has run once for this run
}

// UseOpenAPISpec satisfies engine.OpenAPIAware: sets the spec to be fuzzed via
// `nuclei -im openapi/swagger` (once per run), generating complete requests
// including the BODY. A DASTRunner instance is created fresh per run, so this
// pass runs once on the first Scan call.
func (r *DASTRunner) UseOpenAPISpec(spec []byte) { r.specBytes = spec }

// Name satisfies engine.Engine.
func (r *DASTRunner) Name() string { return "nuclei-dast" }

// UseProxy satisfies engine.ProxyAware: crawl + fuzz are pointed at the egress proxy.
func (r *DASTRunner) UseProxy(addr string) { r.proxyAddr = addr }

// UseAuthHeaders satisfies engine.AuthAware: injects the auth headers (-H) into
// crawl (katana) & fuzz (nuclei -dast) to reach endpoints behind a login (Lever 1).
func (r *DASTRunner) UseAuthHeaders(h []string) { r.authHeaders = h }

const maxDASTURLs = 150 // cap on URLs fuzzed per target (request volume under control)

// Scan satisfies engine.Engine.
func (r *DASTRunner) Scan(ctx context.Context, target, program, runID string) ([]*finding.Finding, error) {
	// Fail-safe: without an egress proxy, make NO connection at all (in line with the
	// principle "never trigger a connection that bypasses the scope guard").
	if r.proxyAddr == "" {
		return nil, nil
	}

	// OpenAPI pass (once per run): fuzz complete requests including the body from the
	// spec. Best-effort: a failure here does not cancel the URL-based fuzz below.
	var extra []*finding.Finding
	if len(r.specBytes) > 0 && !r.specDone {
		r.specDone = true
		extra = r.fuzzOpenAPI(ctx, program, runID)
	}

	// 1) Expand the target into a URL list (best-effort crawl; the target is always included).
	urls := r.gatherURLs(ctx, target)

	// 2) Write the URL list to a temp file for `nuclei -list`.
	listFile, cleanup, err := writeList(urls)
	if err != nil {
		return nil, fmt.Errorf("nuclei-dast: list file: %w", err)
	}
	defer cleanup()

	// 3) Run nuclei -dast over the list (through the egress proxy).
	bin := r.Binary
	if bin == "" {
		bin = "nuclei"
	}
	cmd := exec.CommandContext(ctx, bin, r.nucleiArgs(listFile)...)
	cmd.Env = egress.ProxyEnv(os.Environ(), "http://"+r.proxyAddr) // belt-and-suspenders
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("nuclei-dast: execution failed: %w (%s)", err, strings.TrimSpace(stderr.String()))
	}
	fromList, err := Parse(&stdout, program, runID)
	if err != nil {
		return nil, err
	}
	return append(extra, fromList...), nil
}

// fuzzOpenAPI runs `nuclei -dast -im openapi/swagger` over the spec set via
// UseOpenAPISpec, generating complete requests (method + BODY) to fuzz, which
// complements the URL-based fuzz that only touches the query. Every request still
// goes through the scope-enforced egress proxy. Best-effort: a failure returns nil.
func (r *DASTRunner) fuzzOpenAPI(ctx context.Context, program, runID string) []*finding.Finding {
	spec, mode := r.specBytes, detectSpecMode(r.specBytes) // mode from the ORIGINAL spec
	if len(headerArgs(r.authHeaders)) > 0 {
		// Authenticated scan: logout route operations in the spec (e.g. Petstore GET
		// /user/logout) kill the session, so they are dropped. An unparseable spec means
		// the pass is skipped (fail-closed).
		var err error
		if spec, err = withoutLogoutPaths(spec); err != nil {
			return nil
		}
	}
	f, err := os.CreateTemp("", "nuclei-openapi-*.yaml")
	if err != nil {
		return nil
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err := f.Write(spec); err != nil {
		_ = f.Close()
		return nil
	}
	if err := f.Close(); err != nil {
		return nil
	}

	bin := r.Binary
	if bin == "" {
		bin = "nuclei"
	}
	cmd := exec.CommandContext(ctx, bin, r.nucleiArgsMode(name, mode)...)
	cmd.Env = egress.ProxyEnv(os.Environ(), "http://"+r.proxyAddr)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil // best-effort: the spec may have no in-scope server / an incomplete format
	}
	findings, _ := Parse(&stdout, program, runID)
	return findings
}

// withoutLogoutPaths returns the spec without logout route `paths` entries
// (engine.IsLogoutPath). It goes through yaml.Node (JSON ⊂ YAML) so the order and
// other values stay intact; the result is YAML.
func withoutLogoutPaths(spec []byte) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(spec, &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("spec is not a mapping")
	}
	root := doc.Content[0]
	for i := 0; i+1 < len(root.Content); i += 2 {
		if paths := root.Content[i+1]; root.Content[i].Value == "paths" && paths.Kind == yaml.MappingNode {
			kept := paths.Content[:0]
			for j := 0; j+1 < len(paths.Content); j += 2 {
				if !engine.IsLogoutPath(paths.Content[j].Value) {
					kept = append(kept, paths.Content[j], paths.Content[j+1])
				}
			}
			paths.Content = kept
		}
	}
	return yaml.Marshal(&doc)
}

// detectSpecMode guesses nuclei's input-mode from the spec contents: "swagger" for
// Swagger 2.0, otherwise "openapi" (OpenAPI 3.x).
func detectSpecMode(spec []byte) string {
	head := strings.ToLower(string(spec))
	if len(head) > 4096 {
		head = head[:4096]
	}
	if strings.Contains(head, "\"swagger\"") || strings.Contains(head, "swagger:") {
		return "swagger"
	}
	return "openapi"
}

// gatherURLs crawls the target (best-effort, through the proxy), filters to
// same-host, dedupes, prioritizes parameterized URLs, then caps the count. The
// target itself is ALWAYS included so fuzzing still runs even when the crawl is empty.
func (r *DASTRunner) gatherURLs(ctx context.Context, target string) []string {
	all := append([]string{target}, r.crawl(ctx, target)...)
	return prioritizeURLs(sameHostURLs(target, all), r.Safety.maxURLs())
}

// crawl runs katana over the target through the egress proxy and returns the URLs
// found. Best-effort: a failure or absence returns nil (fuzz the target only).
func (r *DASTRunner) crawl(ctx context.Context, target string) []string {
	bin := r.Katana
	if bin == "" {
		bin = "katana"
	}
	cmd := exec.CommandContext(ctx, bin, r.katanaArgs(target)...)
	cmd.Env = egress.ProxyEnv(os.Environ(), "http://"+r.proxyAddr)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return nil
	}
	var urls []string
	sc := bufio.NewScanner(&out)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if ln := strings.TrimSpace(sc.Text()); ln != "" {
			urls = append(urls, ln)
		}
	}
	return urls
}

func (r *DASTRunner) katanaArgs(target string) []string {
	// -jc: crawl JS (important for an SPA that registers API endpoints in a JS bundle).
	// -d 2: limit the depth to keep the crawl bounded.
	a := []string{"-silent", "-u", target, "-d", "2", "-jc", "-proxy", "http://" + r.proxyAddr}
	if h := headerArgs(r.authHeaders); len(h) > 0 { // Lever 1: crawl behind a login,
		a = append(a, h...) // without following a logout link (the session dies; live 2026-11-16)
		a = append(a, "-cos", engine.LogoutPattern)
	}
	a = append(a, r.Safety.katanaExtraArgs()...)
	if rl := r.Safety.rate(r.RateLimit); rl > 0 {
		a = append(a, "-rate-limit", strconv.Itoa(rl))
	}
	return a
}

// nucleiArgs builds the fuzz arguments for a URL list (mode "list").
func (r *DASTRunner) nucleiArgs(listFile string) []string {
	return r.nucleiArgsMode(listFile, "")
}

// nucleiArgsMode builds the `nuclei -dast` arguments. An empty inputMode means a
// plain URL list; "openapi"/"swagger" means read inputFile as a spec and generate
// requests (including the body). The safety arguments (non-destructive always +
// stealth) are the same for both modes.
func (r *DASTRunner) nucleiArgsMode(inputFile, inputMode string) []string {
	agg := strings.TrimSpace(r.Aggression)
	if agg == "" {
		agg = "low" // fewest payloads; enough for draft->verify candidates
	}
	a := []string{
		"-dast", "-jsonl", "-silent", "-disable-update-check",
		"-list", inputFile,
		"-proxy", "http://" + r.proxyAddr,
		"-fuzz-aggression", agg,
	}
	if inputMode != "" {
		// -skip-format-validation: tolerant of an incomplete spec (best-effort).
		a = append(a, "-input-mode", inputMode, "-skip-format-validation")
		if r.Safety.Stealth {
			// Stealth: required fields only -> fewer requests (minimal footprint).
			a = append(a, "-required-only")
		}
	}
	a = append(a, headerArgs(r.authHeaders)...) // Lever 1: fuzz requests behind a login
	// Safety arguments: non-destructive (always) + stealth (when active).
	a = append(a, r.Safety.nucleiExtraArgs()...)
	if rl := r.Safety.rate(r.RateLimit); rl > 0 {
		a = append(a, "-rate-limit", strconv.Itoa(rl))
	}
	return a
}

// sameHostURLs filters urls to the same host as the target (fuzzing only touches
// the target host; the egress proxy still gates every request as a hard
// boundary), dedupes, keeps the order.
func sameHostURLs(target string, urls []string) []string {
	base, err := url.Parse(target)
	if err != nil || base.Host == "" {
		return dedupURLs(urls)
	}
	seen := map[string]bool{}
	var out []string
	for _, u := range urls {
		pu, err := url.Parse(strings.TrimSpace(u))
		if err != nil || pu.Host == "" {
			continue
		}
		if !strings.EqualFold(pu.Host, base.Host) {
			continue
		}
		s := pu.String()
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// prioritizeURLs puts parameterized URLs (with a query) first, the most valuable
// fuzz points, then caps the total count at limit.
func prioritizeURLs(urls []string, limit int) []string {
	var withQ, rest []string
	for _, u := range urls {
		if strings.Contains(u, "?") {
			withQ = append(withQ, u)
		} else {
			rest = append(rest, u)
		}
	}
	out := append(withQ, rest...)
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func dedupURLs(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// writeList writes the URLs (one per line) to a temp file for `nuclei -list`.
func writeList(urls []string) (string, func(), error) {
	f, err := os.CreateTemp("", "nuclei-dast-*.txt")
	if err != nil {
		return "", func() {}, err
	}
	name := f.Name()
	cleanup := func() { _ = os.Remove(name) }
	if _, err := f.WriteString(strings.Join(urls, "\n") + "\n"); err != nil {
		_ = f.Close()
		cleanup()
		return "", func() {}, err
	}
	if err := f.Close(); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return name, cleanup, nil
}
