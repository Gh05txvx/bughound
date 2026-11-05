package ffuf

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Enrichment robots.txt. robots.txt mengiklankan path yang ingin disembunyikan
// pemilik situs (Disallow/Allow) — justru kandidat probe bernilai tinggi bagi
// hunter (mis. juice-shop: "Disallow: /ftp" -> direktori ter-ekspos). bughound
// mengambilnya lewat proxy egress yang SAMA dengan ffuf, jadi fetch robots.txt
// pun ditegakkan scope guard; dan tiap path hasil parse tetap diprobe ffuf lewat
// proxy itu (lapis kedua). Best-effort: gagal/absen = tanpa enrichment, bukan
// error.

const (
	maxRobotsBytes = 256 * 1024       // batas baca body robots.txt (hindari body raksasa)
	maxRobotsPaths = 200              // batas path yang diambil (hindari wordlist membengkak)
	robotsTimeout  = 10 * time.Second // batas waktu fetch robots.txt
)

// robotsPaths mengambil & mem-parse BASE/robots.txt lewat proxy egress. Tanpa
// proxy (mis. mock/test) TIDAK ada fetch — supaya tak pernah ada koneksi ke
// target yang memintas scope guard.
func (r *Runner) robotsPaths(ctx context.Context, target string) []string {
	if r.proxyAddr == "" {
		return nil // tak ada proxy scope-enforcing -> jangan fetch (fail-safe)
	}
	base := baseOf(target)
	if base == "" {
		return nil
	}
	client, err := proxiedClient(r.proxyAddr, robotsTimeout)
	if err != nil {
		return nil
	}
	return robotsPathsFrom(ctx, client, base)
}

// proxiedClient membuat http.Client yang menyalurkan SEMUA request lewat proxy
// egress (http.Transport.Proxy), sehingga scope guard mengevaluasi tiap koneksi.
// Sertifikat tak diverifikasi, sama seperti engine: proxy membuka TLS host yang punya
// eksklusi ber-path, dan klien yang memverifikasi akan gagal diam-diam di sana.
func proxiedClient(proxyAddr string, timeout time.Duration) (*http.Client, error) {
	pu, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}, nil
}

// robotsPathsFrom melakukan GET base/robots.txt dengan client apa adanya lalu
// mem-parse hasilnya. Dipisah agar bisa diuji tanpa proxy (client langsung).
func robotsPathsFrom(ctx context.Context, client *http.Client, base string) []string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/robots.txt", nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil // robots.txt absen/diblok scope -> tanpa enrichment
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxRobotsBytes))
	return parseRobotsPaths(body, maxRobotsPaths)
}

// parseRobotsPaths mengekstrak path literal dari direktif Disallow/Allow. Hanya
// path relatif ("/...") yang diterima; pola wildcard (*, $) dan URL absolut
// dibuang karena bukan path probe literal. Nilai dikembalikan dalam bentuk FUZZ
// (tanpa slash tepi), ter-dedup, dan dibatasi max.
func parseRobotsPaths(body []byte, max int) []string {
	var out []string
	seen := map[string]bool{}
	for _, raw := range strings.Split(string(body), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(line[:colon])) {
		case "disallow", "allow":
		default:
			continue
		}
		val := strings.TrimSpace(line[colon+1:])
		if h := strings.IndexByte(val, '#'); h >= 0 { // komentar inline
			val = strings.TrimSpace(val[:h])
		}
		val = strings.SplitN(val, "?", 2)[0] // buang query
		if val == "" || val == "/" || !strings.HasPrefix(val, "/") {
			continue // kosong / seluruh situs / bukan path relatif
		}
		if strings.ContainsAny(val, "*$") {
			continue // pola wildcard, bukan path literal
		}
		val = strings.Trim(val, "/") // bentuk FUZZ (tanpa slash tepi)
		if val == "" || strings.ContainsAny(val, " \t") {
			continue
		}
		if seen[val] {
			continue
		}
		seen[val] = true
		out = append(out, val)
		if len(out) >= max {
			break
		}
	}
	return out
}

// mergeWordlist menulis wordlist sementara baru = isi base + path extra (ter-dedup
// terhadap base). base (wordlist bawaan atau milik pengguna) TIDAK diubah.
func mergeWordlist(basePath string, extra []string) (string, func(), error) {
	base, err := os.ReadFile(basePath)
	if err != nil {
		return "", nil, err
	}
	existing := map[string]bool{}
	for _, ln := range strings.Split(string(base), "\n") {
		if ln = strings.TrimSpace(ln); ln != "" {
			existing[ln] = true
		}
	}
	var buf bytes.Buffer
	buf.Write(base)
	if len(base) > 0 && base[len(base)-1] != '\n' {
		buf.WriteByte('\n')
	}
	for _, p := range extra {
		if existing[p] {
			continue
		}
		existing[p] = true
		buf.WriteString(p)
		buf.WriteByte('\n')
	}
	tmp, err := os.CreateTemp("", "ffuf-wl-robots-*.txt")
	if err != nil {
		return "", nil, err
	}
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", nil, err
	}
	tmp.Close()
	return tmp.Name(), func() { os.Remove(tmp.Name()) }, nil
}
