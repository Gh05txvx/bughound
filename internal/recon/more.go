package recon

import (
	"context"
	"net/url"
	"strconv"
	"strings"
)

// Extra recon tools. NONE of them goes through the HTTP proxy:
//   - Gau: PASSIVE (queries web archives such as Wayback/CommonCrawl, not the target).
//   - Dnsx: queries DNS resolvers (not the target application).
//   - Naabu: ACTIVE port scan over raw TCP. It cannot go through an HTTP proxy,
//     so it only runs against hosts ALREADY proven in scope (httpx output that
//     passed the egress proxy), which keeps the "never touch out-of-scope"
//     principle.

// Gau collects historical URLs (passive).
type Gau struct{ Binary string }

func (g *Gau) bin() string {
	if g.Binary != "" {
		return g.Binary
	}
	return "gau"
}

func (g *Gau) args() []string { return []string{"--threads", "5", "--subs"} }

// Collect reads domains from stdin and returns historical URLs.
func (g *Gau) Collect(ctx context.Context, domains []string) ([]string, error) {
	domains = nonEmpty(domains)
	if len(domains) == 0 {
		return nil, nil
	}
	return runLines(ctx, g.bin(), strings.Join(domains, "\n"), nil, g.args()...)
}

// Dnsx validates/resolves hosts through DNS.
type Dnsx struct{ Binary string }

func (d *Dnsx) bin() string {
	if d.Binary != "" {
		return d.Binary
	}
	return "dnsx"
}

func (d *Dnsx) args() []string { return []string{"-silent"} }

// Resolve reads hosts from stdin and returns the ones that resolve.
func (d *Dnsx) Resolve(ctx context.Context, hosts []string) ([]string, error) {
	hosts = nonEmpty(hosts)
	if len(hosts) == 0 {
		return nil, nil
	}
	return runLines(ctx, d.bin(), strings.Join(hosts, "\n"), nil, d.args()...)
}

// Naabu scans for open ports (TCP connect scan, no libpcap at runtime).
type Naabu struct {
	Binary string
	rate   int // -rate (packets/s); 0 = naabu's default
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

// ScanPorts reads hosts from stdin and returns the open "host:port" pairs.
func (n *Naabu) ScanPorts(ctx context.Context, hosts []string) ([]string, error) {
	hosts = nonEmpty(hosts)
	if len(hosts) == 0 {
		return nil, nil
	}
	return runLines(ctx, n.bin(), strings.Join(hosts, "\n"), nil, n.args()...)
}

// hostsFromURLs extracts the unique hosts from a list of URLs (e.g. httpx output).
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
