package recon

import (
	"context"
	"net/url"
	"strconv"
	"strings"
)

// Tool recon tambahan. Semua TIDAK lewat proxy HTTP:
//   - Gau: PASIF (query arsip web seperti Wayback/CommonCrawl, bukan target).
//   - Dnsx: query resolver DNS (bukan aplikasi target).
//   - Naabu: port scan AKTIF via TCP mentah — tak bisa lewat proxy HTTP, maka
//     hanya dijalankan pada host yang SUDAH terbukti in-scope (keluaran httpx
//     yang melewati proxy egress), sehingga prinsip "tak menyentuh out-of-scope"
//     tetap terjaga.

// Gau mengumpulkan URL historis (pasif).
type Gau struct{ Binary string }

func (g *Gau) bin() string {
	if g.Binary != "" {
		return g.Binary
	}
	return "gau"
}

func (g *Gau) args() []string { return []string{"--threads", "5", "--subs"} }

// Collect membaca domain dari stdin dan mengembalikan URL historis.
func (g *Gau) Collect(ctx context.Context, domains []string) ([]string, error) {
	domains = nonEmpty(domains)
	if len(domains) == 0 {
		return nil, nil
	}
	return runLines(ctx, g.bin(), strings.Join(domains, "\n"), nil, g.args()...)
}

// Dnsx memvalidasi/mengresolve host via DNS.
type Dnsx struct{ Binary string }

func (d *Dnsx) bin() string {
	if d.Binary != "" {
		return d.Binary
	}
	return "dnsx"
}

func (d *Dnsx) args() []string { return []string{"-silent"} }

// Resolve membaca host dari stdin dan mengembalikan host yang resolve.
func (d *Dnsx) Resolve(ctx context.Context, hosts []string) ([]string, error) {
	hosts = nonEmpty(hosts)
	if len(hosts) == 0 {
		return nil, nil
	}
	return runLines(ctx, d.bin(), strings.Join(hosts, "\n"), nil, d.args()...)
}

// Naabu memindai port terbuka (TCP connect scan — tanpa libpcap runtime).
type Naabu struct {
	Binary string
	rate   int // -rate (paket/dtk); 0 = default naabu
}

func (n *Naabu) bin() string {
	if n.Binary != "" {
		return n.Binary
	}
	return "naabu"
}

func (n *Naabu) args() []string {
	a := []string{"-silent", "-scan-type", "c"}
	if n.rate > 0 {
		a = append(a, "-rate", strconv.Itoa(n.rate))
	}
	return a
}

// ScanPorts membaca host dari stdin dan mengembalikan "host:port" terbuka.
func (n *Naabu) ScanPorts(ctx context.Context, hosts []string) ([]string, error) {
	hosts = nonEmpty(hosts)
	if len(hosts) == 0 {
		return nil, nil
	}
	return runLines(ctx, n.bin(), strings.Join(hosts, "\n"), nil, n.args()...)
}

// hostsFromURLs mengekstrak host unik dari daftar URL (mis. keluaran httpx).
func hostsFromURLs(urls []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, raw := range urls {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		h := raw
		if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
			h = u.Hostname()
		}
		if !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	return out
}

func nonEmpty(in []string) []string {
	var out []string
	for _, s := range in {
		if strings.TrimSpace(s) != "" {
			out = append(out, strings.TrimSpace(s))
		}
	}
	return out
}
