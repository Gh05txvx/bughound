package recon

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"bughound/internal/egress"
	"bughound/internal/engine"
)

// RealPipeline runs REAL recon through subprocesses: subfinder (passive, OSINT)
// → httpx (probe live hosts) → katana (crawl). httpx and katana TOUCH the
// target, so both are pointed at the egress proxy (ProxyAware) and scope is
// enforced per connection. subfinder is PASSIVE (it contacts OSINT sources, not
// the target), so it does NOT go through the proxy, which is the correct
// behaviour.
//
// An opt-in building block: it is used only with `-engine real`, and only
// against authorized targets. It is not run in dev/test environments.
type RealPipeline struct {
	Subfinder Subfinder
	Httpx     *Httpx
	Katana    *Katana
	// Optional extras (nil = skipped). Gau is passive; Dnsx queries resolvers;
	// Naabu is an active port scan that only touches in-scope hosts (see Discover).
	Gau   *Gau
	Dnsx  *Dnsx
	Naabu *Naabu
}

// NewRealPipelineRate creates a pipeline with the default tools (binaries on
// PATH) and clamps the request rate of the ACTIVE stages (httpx, katana, naabu)
// to rate req/s (0 = the tool's default, no extra rate limit). The passive
// stages (subfinder, gau) and DNS queries (dnsx) do not touch the target, so
// they are not clamped.
func NewRealPipelineRate(rate int) *RealPipeline {
	return &RealPipeline{
		Httpx:  &Httpx{rate: rate},
		Katana: &Katana{rate: rate},
		Gau:    &Gau{},
		Dnsx:   &Dnsx{},
		Naabu:  &Naabu{rate: rate},
	}
}

func (p *RealPipeline) Name() string {
	return "recon (subfinder/gau→dnsx→httpx→naabu/katana)"
}

// UseProxy satisfies engine.ProxyAware: only the active stages (httpx, katana)
// are pointed at the proxy; passive subfinder is left alone.
func (p *RealPipeline) UseProxy(addr string) {
	p.Httpx.proxyAddr = addr
	p.Katana.proxyAddr = addr
}

// UseAuthHeaders satisfies engine.AuthAware: the active stages (httpx probe,
// katana crawl) send the auth headers (-H) so recon reaches content behind the
// login (Lever 1). It does not apply to subfinder/naabu (passive/TCP).
func (p *RealPipeline) UseAuthHeaders(h []string) {
	p.Httpx.authHeaders = h
	p.Katana.authHeaders = h
}

// Discover runs the pipeline for every seed. The order keeps the "never touch
// out-of-scope" principle: the active HTTP stages (httpx, katana) go through
// the egress proxy, and naabu (raw TCP, cannot be proxied) only runs against
// hosts ALREADY proven in scope by httpx output.
func (p *RealPipeline) Discover(ctx context.Context, seeds []string) ([]Asset, error) {
	var assets []Asset

	// 1. subfinder (passive) → hosts (subdomains + seed).
	var hosts []string
	for _, d := range seeds {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		subs, err := p.Subfinder.Enumerate(ctx, d)
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, append(subs, d)...)
	}
	for _, h := range hosts {
		assets = append(assets, Asset{Value: h, Source: "subfinder"})
	}

	// 2. gau (passive) → historical URLs from web archives.
	if p.Gau != nil {
		urls, err := p.Gau.Collect(ctx, seeds)
		if err != nil {
			return nil, err
		}
		for _, u := range urls {
			assets = append(assets, Asset{Value: u, Source: "gau"})
		}
	}

	// 3. dnsx (resolver queries) → hosts that resolve; used as probe candidates.
	probeHosts := hosts
	if p.Dnsx != nil {
		resolved, err := p.Dnsx.Resolve(ctx, hosts)
		if err != nil {
			return nil, err
		}
		for _, h := range resolved {
			assets = append(assets, Asset{Value: h, Source: "dnsx"})
		}
		if len(resolved) > 0 {
			probeHosts = resolved
		}
	}

	// 4. httpx (active, via the egress proxy) → live URLs that are CERTAINLY in scope.
	live, err := p.Httpx.Probe(ctx, probeHosts)
	if err != nil {
		return nil, err
	}
	for _, u := range live {
		assets = append(assets, Asset{Value: u, Source: "httpx"})
	}

	// 5. naabu (active, raw TCP, NOT proxied): only against in-scope hosts from httpx.
	if p.Naabu != nil {
		ports, err := p.Naabu.ScanPorts(ctx, hostsFromURLs(live))
		if err != nil {
			return nil, err
		}
		for _, hp := range ports {
			assets = append(assets, Asset{Value: hp, Source: "naabu"})
		}
	}

	// 6. katana (active, via the egress proxy) → crawl the live URLs.
	crawled, err := p.Katana.Crawl(ctx, live)
	if err != nil {
		return nil, err
	}
	for _, u := range crawled {
		assets = append(assets, Asset{Value: u, Source: "katana"})
	}
	return assets, nil
}

// Subfinder: passive subdomain enumeration.
type Subfinder struct{ Binary string }

func (s Subfinder) bin() string {
	if s.Binary != "" {
		return s.Binary
	}
	return "subfinder"
}

func (s Subfinder) args(domain string) []string { return []string{"-silent", "-d", domain} }

func (s Subfinder) Enumerate(ctx context.Context, domain string) ([]string, error) {
	if domain == "" {
		return nil, nil
	}
	return runLines(ctx, s.bin(), "", nil, s.args(domain)...) // passive: no proxy
}

// Httpx: probes live hosts (active → goes through the egress proxy).
type Httpx struct {
	Binary      string
	rate        int // -rate-limit (req/dtk); 0 = default httpx
	proxyAddr   string
	authHeaders []string // Lever 1: auth headers injected with -H
}

func (h *Httpx) bin() string {
	if h.Binary != "" {
		return h.Binary
	}
	return "httpx"
}

func (h *Httpx) args() []string {
	a := []string{"-silent"}
	if h.proxyAddr != "" {
		a = append(a, "-http-proxy", "http://"+h.proxyAddr)
	}
	if h.rate > 0 {
		a = append(a, "-rate-limit", strconv.Itoa(h.rate))
	}
	for _, hd := range h.authHeaders { // Lever 1: probe behind the login
		if strings.TrimSpace(hd) != "" {
			a = append(a, "-H", hd)
		}
	}
	return a
}

func (h *Httpx) Probe(ctx context.Context, hosts []string) ([]string, error) {
	if len(hosts) == 0 {
		return nil, nil
	}
	return runLines(ctx, h.bin(), strings.Join(hosts, "\n"), h.proxyEnvOrNil(), h.args()...)
}

func (h *Httpx) proxyEnvOrNil() []string {
	if h.proxyAddr == "" {
		return nil
	}
	return egress.ProxyEnv(os.Environ(), "http://"+h.proxyAddr)
}

// Katana: crawling (active → goes through the egress proxy).
type Katana struct {
	Binary      string
	rate        int // -rate-limit (req/dtk); 0 = default katana
	proxyAddr   string
	authHeaders []string // Lever 1: auth headers injected with -H
}

func (k *Katana) bin() string {
	if k.Binary != "" {
		return k.Binary
	}
	return "katana"
}

func (k *Katana) args() []string {
	// -jc: crawl JS, i.e. extract endpoints from JS bundles (SPA routes and API
	// endpoints that do not show up in static HTML). Static, with NO headless
	// browser. -d 3: an explicit depth (deterministic across versions,
	// conservative). The surface this recon finds feeds EVERY non-crawling engine
	// (nuclei/ffuf/zap/dalfox) through the orchestrator, so a shallow crawl
	// shrinks the recall of the whole roster. It stays unauthenticated and goes
	// through the egress proxy/scope guard/rate limiter (see Crawl).
	a := []string{"-silent", "-jc", "-d", "3"}
	if k.proxyAddr != "" {
		a = append(a, "-proxy", "http://"+k.proxyAddr)
	}
	if k.rate > 0 {
		a = append(a, "-rate-limit", strconv.Itoa(k.rate))
	}
	auth := false
	for _, hd := range k.authHeaders { // Lever 1: crawl behind the login (when set)
		if strings.TrimSpace(hd) != "" {
			a = append(a, "-H", hd)
			auth = true
		}
	}
	if auth { // do not follow logout links: one GET kills the login session (seen live 2026-11-16)
		a = append(a, "-cos", engine.LogoutPattern)
	}
	return a
}

func (k *Katana) Crawl(ctx context.Context, urls []string) ([]string, error) {
	if len(urls) == 0 {
		return nil, nil
	}
	var env []string
	if k.proxyAddr != "" {
		env = egress.ProxyEnv(os.Environ(), "http://"+k.proxyAddr)
	}
	return runLines(ctx, k.bin(), strings.Join(urls, "\n"), env, k.args()...)
}

// runLines runs a line-based tool (stdin optional) and returns the non-empty
// stdout lines.
func runLines(ctx context.Context, bin, stdin string, env []string, args ...string) ([]string, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	if env != nil {
		cmd.Env = env
	}
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("recon %s failed: %w (%s)", bin, err, strings.TrimSpace(errb.String()))
	}
	var lines []string
	for _, ln := range strings.Split(out.String(), "\n") {
		if ln = strings.TrimSpace(ln); ln != "" {
			lines = append(lines, ln)
		}
	}
	return lines, nil
}
