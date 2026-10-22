package recon

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
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
}

// NewRealPipeline membuat pipeline dengan tool default (binary di PATH).
func NewRealPipeline() *RealPipeline {
	return &RealPipeline{Httpx: &Httpx{}, Katana: &Katana{}}
}

func (p *RealPipeline) Name() string { return "recon (subfinder→httpx→katana)" }

// UseProxy memenuhi engine.ProxyAware: hanya tahap aktif (httpx, katana) yang
// diarahkan ke proxy; subfinder pasif dibiarkan.
func (p *RealPipeline) UseProxy(addr string) {
	p.Httpx.proxyAddr = addr
	p.Katana.proxyAddr = addr
}

// Discover menjalankan pipeline untuk seluruh seed.
func (p *RealPipeline) Discover(ctx context.Context, seeds []string) ([]Asset, error) {
	var assets []Asset
	var hosts []string
	for _, d := range seeds {
		subs, err := p.Subfinder.Enumerate(ctx, strings.TrimSpace(d))
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, subs...)
	}
	for _, h := range hosts {
		assets = append(assets, Asset{Value: h, Source: "subfinder"})
	}

	live, err := p.Httpx.Probe(ctx, hosts)
	if err != nil {
		return nil, err
	}
	for _, u := range live {
		assets = append(assets, Asset{Value: u, Source: "httpx"})
	}

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
	return runLines(ctx, s.bin(), "", s.args(domain)...)
}

// Httpx: probe host hidup (aktif → lewat proxy egress).
type Httpx struct {
	Binary    string
	proxyAddr string
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
	return a
}

func (h *Httpx) Probe(ctx context.Context, hosts []string) ([]string, error) {
	if len(hosts) == 0 {
		return nil, nil
	}
	return runLines(ctx, h.bin(), strings.Join(hosts, "\n"), h.args()...)
}

// Katana: crawling (aktif → lewat proxy egress).
type Katana struct {
	Binary    string
	proxyAddr string
}

func (k *Katana) bin() string {
	if k.Binary != "" {
		return k.Binary
	}
	return "katana"
}

func (k *Katana) args() []string {
	a := []string{"-silent"}
	if k.proxyAddr != "" {
		a = append(a, "-proxy", "http://"+k.proxyAddr)
	}
	return a
}

func (k *Katana) Crawl(ctx context.Context, urls []string) ([]string, error) {
	if len(urls) == 0 {
		return nil, nil
	}
	return runLines(ctx, k.bin(), strings.Join(urls, "\n"), k.args()...)
}

// runLines menjalankan tool berbasis baris (stdin opsional) dan mengembalikan
// baris stdout yang tidak kosong.
func runLines(ctx context.Context, bin, stdin string, args ...string) ([]string, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
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
