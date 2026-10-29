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
// Wordlist opsional: bila kosong, dipakai wordlist bawaan (DefaultWordlist).
// Koneksi keluar wajib lewat proxy egress bughound (UseProxy -> ffuf -x),
// sehingga tiap request diperiksa scope guard SEBELUM koneksi dibuat. Bukan
// default; aktifkan secara sadar untuk target yang sah.
type Runner struct {
	Binary    string // default "ffuf"
	Wordlist  string // -w; kosong = wordlist bawaan
	RateLimit int    // -rate (req/dtk); 0 = default ffuf
	proxyAddr string
}

// Name memenuhi engine.Engine.
func (r *Runner) Name() string { return "ffuf" }

// UseProxy memenuhi engine.ProxyAware: mengarahkan ffuf ke proxy egress.
func (r *Runner) UseProxy(addr string) { r.proxyAddr = addr }

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
	defer cleanupWL()

	tmp, err := os.CreateTemp("", "ffuf-*.json")
	if err != nil {
		return nil, fmt.Errorf("ffuf: berkas sementara: %w", err)
	}
	out := tmp.Name()
	tmp.Close()
	defer os.Remove(out)

	cmd := exec.CommandContext(ctx, bin, r.buildArgs(target, out, wordlist)...)
	if r.proxyAddr != "" {
		cmd.Env = egress.ProxyEnv(os.Environ(), "http://"+r.proxyAddr) // belt-and-suspenders
	}
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
	return args
}
