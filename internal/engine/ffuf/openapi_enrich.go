package ffuf

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"

	"bughound/internal/openapi"
)

// Enrichment OpenAPI/Swagger. Banyak API memublikasikan spec di lokasi well-known
// (atau menyematkannya di swagger-ui-init.js). Endpoint terdokumentasi adalah
// kandidat probe bernilai tinggi. bughound mengambil spec lewat proxy egress yang
// SAMA dengan ffuf (scope-enforced), mem-parse-nya via paket internal/openapi,
// lalu menggabungkan PATH endpoint ke wordlist (diprobe ffuf -> temuan
// exposed-path). Best-effort: tak ada spec/parse gagal = tanpa enrichment, bukan
// error.

// Lokasi spec well-known (standalone JSON/YAML) + swagger-ui-init.js (JS-embedded).
var specLocations = []string{
	"/openapi.json",
	"/swagger.json",
	"/v3/api-docs",
	"/v2/api-docs",
	"/api-docs.json",
	"/swagger/v1/swagger.json",
	"/api-docs/swagger-ui-init.js", // swagger-ui menyematkan "swaggerDoc": {...}
}

const maxSpecPaths = 300 // batas endpoint yang diambil dari spec

// specPaths mengambil spec dari lokasi well-known lewat proxy egress lalu
// mengembalikan PATH endpoint (bentuk FUZZ). Tanpa proxy -> nil (fail-safe:
// tak pernah ada koneksi ke target yang memintas scope guard).
func (r *Runner) specPaths(ctx context.Context, target string) []string {
	if r.proxyAddr == "" {
		return nil
	}
	base := baseOf(target)
	if base == "" {
		return nil
	}
	client, err := proxiedClient(r.proxyAddr, robotsTimeout)
	if err != nil {
		return nil
	}
	return specPathsFrom(ctx, client, base)
}

// specPathsFrom mencoba tiap lokasi well-known dengan client apa adanya dan
// mengembalikan path dari spec pertama yang valid. Dipisah agar bisa diuji tanpa
// proxy (client langsung ke server uji).
func specPathsFrom(ctx context.Context, client *http.Client, base string) []string {
	base = strings.TrimRight(base, "/")
	for _, loc := range specLocations {
		body := fetchBody(ctx, client, base+loc)
		if len(body) == 0 {
			continue
		}
		if strings.HasSuffix(loc, ".js") {
			body = extractSwaggerDoc(body) // ambil objek swaggerDoc dari JS swagger-ui
		}
		if !looksLikeSpec(body) {
			continue // hindari mem-parse HTML catch-all SPA sebagai spec
		}
		eps, err := openapi.Endpoints(body, base)
		if err != nil {
			continue
		}
		if paths := endpointPaths(eps); len(paths) > 0 {
			return paths
		}
	}
	return nil
}

// fetchBody GET sebuah URL dan mengembalikan body (dibatasi) hanya bila 200.
func fetchBody(ctx context.Context, client *http.Client, u string) []byte {
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
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4*maxRobotsBytes)) // spec bisa > robots
	return body
}

// looksLikeSpec: sniff cepat supaya HTML catch-all SPA tak diumpankan ke parser.
// Semua spec OpenAPI/Swagger punya objek "paths".
func looksLikeSpec(body []byte) bool {
	s := strings.TrimSpace(string(body))
	if s == "" || strings.HasPrefix(s, "<") {
		return false // kosong atau HTML
	}
	return strings.Contains(s, "\"paths\"") || strings.Contains(s, "paths:")
}

// extractSwaggerDoc mengekstrak objek JSON setelah "swaggerDoc": dari isi
// swagger-ui-init.js (penghitungan kurung berimbang, abai kurung di dalam string).
// Kosong bila tak ditemukan.
func extractSwaggerDoc(js []byte) []byte {
	s := string(js)
	i := strings.Index(s, "\"swaggerDoc\"")
	if i < 0 {
		return nil
	}
	j := strings.IndexByte(s[i:], '{')
	if j < 0 {
		return nil
	}
	start := i + j
	depth, inStr, esc := 0, false, false
	for k := start; k < len(s); k++ {
		c := s[k]
		if inStr {
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return []byte(s[start : k+1])
			}
		}
	}
	return nil
}

// endpointPaths mengubah URL endpoint absolut (keluaran openapi.Endpoints) menjadi
// PATH bentuk FUZZ (tanpa slash tepi). Host diabaikan — path tetap diprobe thd
// target scan & ditegakkan scope guard saat probe. Ter-dedup & dibatasi.
func endpointPaths(urls []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, u := range urls {
		pu, err := url.Parse(u)
		if err != nil {
			continue
		}
		p := strings.Trim(pu.Path, "/")
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
		if len(out) >= maxSpecPaths {
			break
		}
	}
	return out
}
