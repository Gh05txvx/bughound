// Package recon discovers assets (subdomains, live hosts, crawled URLs) from
// seed domains. The MOCK pipeline in this file (subfinder → httpx → katana)
// returns recorded data without touching the network, so the recon → scope
// guard → DAST flow can be tested safely.
//
// Discovered assets STILL have to pass the scope guard before they are used as
// DAST targets; recon grants no privilege to bypass scope.
package recon

import (
	"context"
	"strings"
)

// Asset is one asset found by recon, with the stage it came from.
type Asset struct {
	Value  string // host, host:port, or URL (e.g. app.demo.test / app.demo.test:8443 / https://app.demo.test/login)
	Source string // "subfinder" | "gau" | "dnsx" | "httpx" | "naabu" | "katana"
}

// Engine runs recon from the seeds and returns the assets it finds.
type Engine interface {
	Name() string
	Discover(ctx context.Context, seeds []string) ([]Asset, error)
}

// MockPipeline simulates subfinder → httpx → katana with no network.
type MockPipeline struct{}

// Name satisfies Engine.
func (MockPipeline) Name() string { return "recon-mock (subfinder→httpx→katana)" }

// Discover satisfies Engine. For each seed it returns subdomains (subfinder),
// live host URLs (httpx) and crawled URLs (katana). One out-of-scope asset is
// included on purpose so the scope guard's filtering can be demonstrated.
func (MockPipeline) Discover(_ context.Context, seeds []string) ([]Asset, error) {
	var out []Asset
	for _, seed := range seeds {
		seed = strings.ToLower(strings.TrimSpace(seed))
		if seed == "" {
			continue
		}
		subs := []string{seed, "app." + seed, "api." + seed, "admin." + seed}
		for _, h := range subs {
			out = append(out, Asset{Value: h, Source: "subfinder"})
		}
		// gau: historical URLs from archives (passive).
		out = append(out,
			Asset{Value: "https://" + seed + "/old/index.php?id=1", Source: "gau"},
			Asset{Value: "https://app." + seed + "/api/v1?debug=true", Source: "gau"},
		)
		// dnsx: hosts that resolve (DNS validation).
		for _, h := range []string{seed, "app." + seed, "api." + seed} {
			out = append(out, Asset{Value: h, Source: "dnsx"})
		}
		for _, h := range subs {
			out = append(out, Asset{Value: "https://" + h, Source: "httpx"})
		}
		// naabu: open ports on in-scope hosts (host:port).
		out = append(out,
			Asset{Value: "app." + seed + ":8443", Source: "naabu"},
			Asset{Value: seed + ":22", Source: "naabu"},
		)
		out = append(out,
			Asset{Value: "https://app." + seed + "/login", Source: "katana"},
			Asset{Value: "https://api." + seed + "/v1/users", Source: "katana"},
		)
	}
	if len(out) > 0 {
		// An out-of-scope asset (e.g. picked up by crawling into another domain).
		out = append(out, Asset{Value: "https://exfil.evil.test/", Source: "katana"})
	}
	return out, nil
}
