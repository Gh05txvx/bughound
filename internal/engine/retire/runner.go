// Package retire adalah adapter engine retire.js: mendeteksi library JavaScript
// sisi-klien yang usang/rentan (CVE) pada aset yang DISAJIKAN target.
//
// retire.js adalah pemindai berbasis berkas (tak meng-crawl URL), jadi adapter
// ini: ambil HTML target -> ekstrak <script src> SAME-ORIGIN -> unduh tiap JS
// lewat proxy egress (scope-enforced) ke dir sementara -> jalankan
// `retire --jspath` -> normalkan output JSON ke Skema Temuan Seragam.
//
// Hanya JS SAME-ORIGIN (in-scope) yang diunduh; library CDN pihak ketiga tidak
// diambil — itu di luar aset target dan akan diblok scope guard. Seperti engine
// lain, koneksi keluar wajib lewat proxy egress (UseProxy dipanggil orchestrator).
package retire

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"bughound/internal/finding"
)

// Runner adalah engine retire.js NYATA.
type Runner struct {
	Binary    string // default "retire"
	RateLimit int    // disimpan utk konsistensi factory; unduhan sedikit, tak dijepit
	proxyAddr string
}

// Name memenuhi engine.Engine.
func (r *Runner) Name() string { return "retire" }

// UseProxy memenuhi engine.ProxyAware: koneksi (fetch HTML + unduh JS) diarahkan
// ke proxy egress sehingga tiap koneksi ditegakkan scope guard.
func (r *Runner) UseProxy(addr string) { r.proxyAddr = addr }

const (
	maxJSFiles   = 40              // batas berkas JS yang diunduh per target
	maxJSBytes   = 8 * 1024 * 1024 // batas ukuran tiap berkas JS
	maxHTMLBytes = 4 * 1024 * 1024 // batas baca HTML target
	fetchTimeout = 20 * time.Second
)

// Scan memenuhi engine.Engine.
func (r *Runner) Scan(ctx context.Context, target, program, runID string) ([]*finding.Finding, error) {
	// Fail-safe: tanpa proxy egress, JANGAN buat koneksi apa pun. Semua egress
	// engine wajib lewat proxy scope-enforced (orchestrator memanggil UseProxy
	// sebelum Scan); proxyAddr kosong = misconfigurasi -> tak ada fetch, selaras
	// prinsip "tidak pernah memicu koneksi yang memintas scope guard".
	if r.proxyAddr == "" {
		return nil, nil
	}
	client, err := r.httpClient()
	if err != nil {
		return nil, fmt.Errorf("retire: client: %w", err)
	}
	html := fetchBody(ctx, client, target, maxHTMLBytes)
	if len(html) == 0 {
		return nil, nil // target tak terjangkau/kosong -> tak ada yang dianalisis
	}
	jsURLs := sameOriginScriptURLs(target, html)
	if len(jsURLs) == 0 {
		return nil, nil
	}

	dir, err := os.MkdirTemp("", "retire-js-*")
	if err != nil {
		return nil, fmt.Errorf("retire: dir sementara: %w", err)
	}
	defer os.RemoveAll(dir)

	fileToURL := map[string]string{}
	n := 0
	for _, ju := range jsURLs {
		if n >= maxJSFiles {
			break
		}
		body := fetchBody(ctx, client, ju, maxJSBytes)
		if len(body) == 0 {
			continue
		}
		name := fmt.Sprintf("%03d.js", n)
		if werr := os.WriteFile(filepath.Join(dir, name), body, 0o600); werr != nil {
			continue
		}
		fileToURL[name] = ju
		n++
	}
	if n == 0 {
		return nil, nil
	}

	out, err := r.runRetire(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("retire: eksekusi gagal: %w", err)
	}
	return Parse(out, fileToURL, target, program, runID)
}

func (r *Runner) bin() string {
	if strings.TrimSpace(r.Binary) != "" {
		return r.Binary
	}
	return "retire"
}

// runRetire menjalankan retire.js atas dir berisi berkas JS yang sudah diunduh.
// --exitwith 0: ditemukannya kerentanan JANGAN membuat exit non-zero (kita baca
// JSON-nya sendiri), agar cmd.Run tak salah mengira itu kegagalan eksekusi.
func (r *Runner) runRetire(ctx context.Context, dir string) ([]byte, error) {
	outFile := filepath.Join(dir, "retire-out.json")
	args := []string{"--jspath", dir, "--outputformat", "json", "--outputpath", outFile, "--exitwith", "0"}
	cmd := exec.CommandContext(ctx, r.bin(), args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w (%s)", err, strings.TrimSpace(stderr.String()))
	}
	return os.ReadFile(outFile)
}

// httpClient membuat client yang menyalurkan request lewat proxy egress bila ada.
func (r *Runner) httpClient() (*http.Client, error) {
	tr := &http.Transport{}
	if r.proxyAddr != "" {
		pu, err := url.Parse("http://" + r.proxyAddr)
		if err != nil {
			return nil, err
		}
		tr.Proxy = http.ProxyURL(pu)
	}
	return &http.Client{Timeout: fetchTimeout, Transport: tr}, nil
}

var scriptSrc = regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']([^"']+)["']`)

// sameOriginScriptURLs mengekstrak URL <script src> dan menyaring hanya yang
// SAME-ORIGIN dgn target (host sama). JS CDN pihak ketiga tidak diambil — di luar
// aset target & akan diblok scope guard.
func sameOriginScriptURLs(target string, html []byte) []string {
	base, err := url.Parse(target)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, m := range scriptSrc.FindAllSubmatch(html, -1) {
		raw := strings.TrimSpace(string(m[1]))
		if raw == "" {
			continue
		}
		u, err := base.Parse(raw) // resolve relatif terhadap target
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			continue
		}
		if !strings.EqualFold(u.Host, base.Host) {
			continue // bukan same-origin
		}
		u.Fragment = ""
		s := u.String()
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// fetchBody GET sebuah URL dan mengembalikan body (dibatasi) hanya bila 200.
func fetchBody(ctx context.Context, client *http.Client, u string, limit int64) []byte {
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
	body, _ := io.ReadAll(io.LimitReader(resp.Body, limit))
	return body
}
