// Package recon menemukan aset (subdomain, host hidup, URL hasil crawling) dari
// seed domain. Di M1 ini diimplementasikan sebagai pipeline MOCK (subfinder →
// httpx → katana) yang mengembalikan data terekam tanpa menyentuh jaringan,
// agar alur recon → scope guard → DAST bisa diuji dengan aman.
//
// Aset yang ditemukan TETAP harus lolos scope guard sebelum dipakai sebagai
// target DAST; recon tidak memberi hak istimewa untuk memintas scope.
package recon

import (
	"context"
	"strings"
)

// Asset adalah satu aset hasil recon beserta tahap sumbernya.
type Asset struct {
	Value  string // host, host:port, atau URL (mis. app.demo.test / app.demo.test:8443 / https://app.demo.test/login)
	Source string // "subfinder" | "gau" | "dnsx" | "httpx" | "naabu" | "katana"
}

// Engine menjalankan recon dari seed dan mengembalikan aset yang ditemukan.
type Engine interface {
	Name() string
	Discover(ctx context.Context, seeds []string) ([]Asset, error)
}

// MockPipeline mensimulasikan subfinder → httpx → katana tanpa jaringan.
type MockPipeline struct{}

// Name memenuhi Engine.
func (MockPipeline) Name() string { return "recon-mock (subfinder→httpx→katana)" }

// Discover memenuhi Engine. Untuk tiap seed menghasilkan subdomain (subfinder),
// URL host hidup (httpx), dan URL crawling (katana). Satu aset di luar scope
// sengaja disertakan agar penyaringan scope guard bisa dibuktikan.
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
		// gau: URL historis dari arsip (pasif).
		out = append(out,
			Asset{Value: "https://" + seed + "/old/index.php?id=1", Source: "gau"},
			Asset{Value: "https://app." + seed + "/api/v1?debug=true", Source: "gau"},
		)
		// dnsx: host yang resolve (validasi DNS).
		for _, h := range []string{seed, "app." + seed, "api." + seed} {
			out = append(out, Asset{Value: h, Source: "dnsx"})
		}
		for _, h := range subs {
			out = append(out, Asset{Value: "https://" + h, Source: "httpx"})
		}
		// naabu: port terbuka pada host in-scope (host:port).
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
		// Aset di luar scope (mis. tertangkap crawling ke domain lain).
		out = append(out, Asset{Value: "https://exfil.evil.test/", Source: "katana"})
	}
	return out, nil
}
