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

// RealPipeline menjalankan recon NYATA via subprocess: subfinder (pasif, OSINT)
// → httpx (probe host hidup) → katana (crawl). httpx & katana MENYENTUH target,
// jadi keduanya diarahkan ke proxy egress (ProxyAware) agar scope ditegakkan
// per koneksi. subfinder PASIF (mengontak sumber OSINT, bukan target) sehingga
// TIDAK lewat proxy — ini perilaku yang benar.
//
// Building block opt-in: hanya dipakai dengan `-engine real`, dan hanya terhadap
// target yang sah. Tidak dijalankan di lingkungan dev/test (CLAUDE.md).
type RealPipeline struct {
	Subfinder Subfinder
	Httpx     *Httpx
	Katana    *Katana
	// Tambahan opsional (nil = dilewati). Gau pasif; Dnsx query resolver; Naabu
	// port scan aktif yang hanya menyentuh host in-scope (lihat Discover).
	Gau   *Gau
	Dnsx  *Dnsx
	Naabu *Naabu
}

// NewRealPipelineRate membuat pipeline dengan tool default (binary di PATH) dan
// menjepit laju request tahap AKTIF (httpx, katana, naabu) ke rate req/dtk
// (0 = default tool, tanpa batas laju tambahan). Tahap pasif (subfinder, gau)
// dan query DNS (dnsx) tidak menyentuh target sehingga tidak ikut dijepit.
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

// UseProxy memenuhi engine.ProxyAware: hanya tahap aktif (httpx, katana) yang
// diarahkan ke proxy; subfinder pasif dibiarkan.
func (p *RealPipeline) UseProxy(addr string) {
	p.Httpx.proxyAddr = addr
	p.Katana.proxyAddr = addr
}

// UseAuthHeaders memenuhi engine.AuthAware: tahap aktif (httpx probe, katana
// crawl) menyertakan header auth (-H) agar recon menjangkau konten di balik
// login (Lever 1). subfinder/naabu (pasif/TCP) tak relevan.
func (p *RealPipeline) UseAuthHeaders(h []string) {
	p.Httpx.authHeaders = h
	p.Katana.authHeaders = h
}

// Discover menjalankan pipeline untuk seluruh seed. Urutan menjaga prinsip
// "tak menyentuh out-of-scope": tahap aktif-HTTP (httpx, katana) lewat proxy
// egress, dan naabu (TCP mentah, tak bisa diproxy) hanya dijalankan pada host
// yang SUDAH terbukti in-scope dari keluaran httpx.
func (p *RealPipeline) Discover(ctx context.Context, seeds []string) ([]Asset, error) {
	var assets []Asset

	// 1. subfinder (pasif) → host (subdomain + seed).
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

	// 2. gau (pasif) → URL historis dari arsip web.
	if p.Gau != nil {
		urls, err := p.Gau.Collect(ctx, seeds)
		if err != nil {
			return nil, err
		}
		for _, u := range urls {
			assets = append(assets, Asset{Value: u, Source: "gau"})
		}
	}

	// 3. dnsx (query resolver) → host yang resolve; dipakai sebagai kandidat probe.
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

	// 4. httpx (aktif, via proxy egress) → URL hidup yang PASTI in-scope.
	live, err := p.Httpx.Probe(ctx, probeHosts)
	if err != nil {
		return nil, err
	}
	for _, u := range live {
		assets = append(assets, Asset{Value: u, Source: "httpx"})
	}

	// 5. naabu (aktif, TCP mentah, TAK diproxy) — hanya pada host in-scope hasil httpx.
	if p.Naabu != nil {
		ports, err := p.Naabu.ScanPorts(ctx, hostsFromURLs(live))
		if err != nil {
			return nil, err
		}
		for _, hp := range ports {
			assets = append(assets, Asset{Value: hp, Source: "naabu"})
		}
	}

	// 6. katana (aktif, via proxy egress) → crawling URL hidup.
	crawled, err := p.Katana.Crawl(ctx, live)
	if err != nil {
		return nil, err
	}
	for _, u := range crawled {
		assets = append(assets, Asset{Value: u, Source: "katana"})
	}
	return assets, nil
}

// Subfinder: enumerasi subdomain pasif.
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
	return runLines(ctx, s.bin(), "", nil, s.args(domain)...) // pasif: tanpa proxy
}

// Httpx: probe host hidup (aktif → lewat proxy egress).
type Httpx struct {
	Binary      string
	rate        int // -rate-limit (req/dtk); 0 = default httpx
	proxyAddr   string
	authHeaders []string // Lever 1: header auth disuntik via -H
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
	for _, hd := range h.authHeaders { // Lever 1: probe di balik login
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

// Katana: crawling (aktif → lewat proxy egress).
type Katana struct {
	Binary      string
	rate        int // -rate-limit (req/dtk); 0 = default katana
	proxyAddr   string
	authHeaders []string // Lever 1: header auth disuntik via -H
}

func (k *Katana) bin() string {
	if k.Binary != "" {
		return k.Binary
	}
	return "katana"
}

func (k *Katana) args() []string {
	// -jc: crawl JS — ekstrak endpoint dari bundel JS (route/endpoint API SPA yang
	// tak terlihat di HTML statis). Statis, TANPA headless/browser. -d 3: depth
	// eksplisit (deterministik lintas-versi, konservatif). Permukaan hasil recon ini
	// memberi makan SEMUA engine non-crawling (nuclei/ffuf/zap/dalfox) lewat
	// orchestrator, jadi crawl yang dangkal mengecilkan recall seluruh roster.
	// Tetap unauth + lewat proxy egress/scope guard/rate limiter (lihat Crawl).
	a := []string{"-silent", "-jc", "-d", "3"}
	if k.proxyAddr != "" {
		a = append(a, "-proxy", "http://"+k.proxyAddr)
	}
	if k.rate > 0 {
		a = append(a, "-rate-limit", strconv.Itoa(k.rate))
	}
	auth := false
	for _, hd := range k.authHeaders { // Lever 1: crawl di balik login (bila ada)
		if strings.TrimSpace(hd) != "" {
			a = append(a, "-H", hd)
			auth = true
		}
	}
	if auth { // jangan ikuti link logout: satu GET mematikan sesi login (live 2026-11-16)
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

// runLines menjalankan tool berbasis baris (stdin opsional) dan mengembalikan
// baris stdout yang tidak kosong.
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
		return nil, fmt.Errorf("recon %s gagal: %w (%s)", bin, err, strings.TrimSpace(errb.String()))
	}
	var lines []string
	for _, ln := range strings.Split(out.String(), "\n") {
		if ln = strings.TrimSpace(ln); ln != "" {
			lines = append(lines, ln)
		}
	}
	return lines, nil
}
