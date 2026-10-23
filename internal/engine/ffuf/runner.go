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
// Butuh wordlist (-w). Koneksi keluar wajib lewat proxy egress bughound
// (UseProxy -> ffuf -x), sehingga tiap request diperiksa scope guard SEBELUM
// koneksi dibuat. Bukan default; aktifkan secara sadar untuk target yang sah.
type Runner struct {
	Binary    string // default "ffuf"
	Wordlist  string // -w (wajib untuk run nyata)
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
	if strings.TrimSpace(r.Wordlist) == "" {
		return nil, fmt.Errorf("ffuf: wordlist (-w) wajib diisi untuk run nyata")
	}
	tmp, err := os.CreateTemp("", "ffuf-*.json")
	if err != nil {
		return nil, fmt.Errorf("ffuf: berkas sementara: %w", err)
	}
	out := tmp.Name()
	tmp.Close()
	defer os.Remove(out)

	cmd := exec.CommandContext(ctx, bin, r.buildArgs(target, out)...)
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

func (r *Runner) buildArgs(target, out string) []string {
	u := target
	if !strings.Contains(u, "FUZZ") {
		u = strings.TrimRight(u, "/") + "/FUZZ"
	}
	args := []string{"-u", u, "-w", r.Wordlist, "-of", "json", "-o", out, "-s"}
	if r.proxyAddr != "" {
		args = append(args, "-x", "http://"+r.proxyAddr)
	}
	if r.RateLimit > 0 {
		args = append(args, "-rate", strconv.Itoa(r.RateLimit))
	}
	return args
}
