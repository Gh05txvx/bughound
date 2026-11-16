package ffuf

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"bughound/internal/egress"
	"bughound/internal/finding"
)

// Runner adalah engine ffuf NYATA: mengeksekusi binary ffuf sebagai subprocess,
// menulis hasil JSON ke berkas sementara, lalu menormalkannya lewat Parse.
//
// Wordlist opsional: bila kosong, dipakai wordlist bawaan (defaultWordlist).
// Koneksi keluar wajib lewat proxy egress bughound (UseProxy -> ffuf -x),
// sehingga tiap request diperiksa scope guard SEBELUM koneksi dibuat. Bukan
// default; aktifkan secara sadar untuk target yang sah.
type Runner struct {
	Binary      string // default "ffuf"
	Wordlist    string // -w; kosong = wordlist bawaan
	RateLimit   int    // -rate (req/dtk); 0 = default ffuf
	APIRoutes   bool   // true = tambahkan wordlist route API ter-bundle (Assetnote apiroutes)
	proxyAddr   string
	authHeaders []string // Lever 1: header auth disuntik via -H (lihat UseAuthHeaders)
}

// Name memenuhi engine.Engine.
func (r *Runner) Name() string { return "ffuf" }

// UseProxy memenuhi engine.ProxyAware: mengarahkan ffuf ke proxy egress.
func (r *Runner) UseProxy(addr string) { r.proxyAddr = addr }

// UseAuthHeaders memenuhi engine.AuthAware: menyuntik header auth (-H) ke tiap
// request ffuf agar fuzzing konten di balik login (Lever 1).
func (r *Runner) UseAuthHeaders(h []string) { r.authHeaders = h }

// Scan memenuhi engine.Engine.
func (r *Runner) Scan(ctx context.Context, target, program, runID string) ([]*finding.Finding, error) {
	bin := r.Binary
	if bin == "" {
		bin = "ffuf"
	}
	wordlist, cleanupWL, err := r.resolveWordlist()
	if err != nil {
		return nil, fmt.Errorf("ffuf: wordlist: %w", err)
	}
	defer func() { cleanupWL() }() // closure: ikut cleanup pengganti bila wordlist di-merge

	// Enrichment (best-effort, lewat proxy egress yang scope-enforced): path yang
	// diiklankan target lewat robots.txt (Disallow/Allow) + endpoint terdokumentasi
	// di spec OpenAPI/Swagger adalah kandidat probe bernilai tinggi (mis. /ftp,
	// /b2b/v2/orders). Tiap path hasil tetap diprobe ffuf lewat proxy yang sama.
	// Gagal/absen = tanpa enrichment, bukan error.
	var extra []string
	extra = append(extra, r.robotsPaths(ctx, target)...)
	extra = append(extra, r.specPaths(ctx, target)...)
	extra = append(extra, r.apiRoutePaths()...) // route API ter-bundle (opt-in, lewat proxy)
	if len(extra) > 0 {
		if merged, cleanupMerged, mErr := mergeWordlist(wordlist, extra); mErr == nil {
			cleanupWL() // buang wordlist dasar
			wordlist, cleanupWL = merged, cleanupMerged
		}
	}

	tmp, err := os.CreateTemp("", "ffuf-*.json")
	if err != nil {
		return nil, fmt.Errorf("ffuf: berkas sementara: %w", err)
	}
	out := tmp.Name()
	tmp.Close()
	defer os.Remove(out)

	// ffuf v2 menyimpan opsi tiap run — TERMASUK nilai header -H (sesi auth) —
	// plaintext ke $XDG_CONFIG_HOME/ffuf/history. Config home bersama = secret
	// menumpuk lintas program di kontainer (terbukti live 2026-11-16) → dir per run.
	cfgDir, err := os.MkdirTemp("", "ffuf-cfg-*")
	if err != nil {
		return nil, fmt.Errorf("ffuf: dir konfigurasi sementara: %w", err)
	}
	defer os.RemoveAll(cfgDir)

	cmd := exec.CommandContext(ctx, bin, r.buildArgs(target, out, wordlist)...)
	env := os.Environ()
	if r.proxyAddr != "" {
		env = egress.ProxyEnv(env, "http://"+r.proxyAddr) // belt-and-suspenders
	}
	cmd.Env = append(env, "XDG_CONFIG_HOME="+cfgDir) // entri env terakhir menang
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ffuf: eksekusi gagal: %w (%s)", err, strings.TrimSpace(stderr.String()))
	}
	data, err := os.ReadFile(out)
	if err != nil {
		return nil, fmt.Errorf("ffuf: baca hasil: %w", err)
	}
	return Parse(bytes.NewReader(data), program, runID)
}

func (r *Runner) buildArgs(target, out, wordlist string) []string {
	u := target
	if !strings.Contains(u, "FUZZ") {
		u = strings.TrimRight(u, "/") + "/FUZZ"
	}
	// -ac: auto-kalibrasi ffuf. ffuf menyelidiki beberapa path acak lebih dulu
	// untuk mempelajari "sidik jari" respons catch-all (mis. SPA yang membalas
	// index.html untuk hampir semua path) lalu menyaringnya DI SUMBER. Ini
	// memangkas banjir positif palsu sekaligus mengurangi request ke target.
	// Parse() tetap punya lapis penekanan sendiri sebagai jaring pengaman.
	args := []string{"-u", u, "-w", wordlist, "-of", "json", "-o", out, "-s", "-ac"}
	if r.proxyAddr != "" {
		args = append(args, "-x", "http://"+r.proxyAddr)
	}
	if r.RateLimit > 0 {
		args = append(args, "-rate", strconv.Itoa(r.RateLimit))
	}
	for _, h := range r.authHeaders { // Lever 1: header auth (bila ada)
		if strings.TrimSpace(h) != "" {
			args = append(args, "-H", h)
		}
	}
	return args
}
