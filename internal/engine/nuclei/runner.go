package nuclei

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"

	"bughound/internal/egress"
	"bughound/internal/finding"
)

// Runner adalah engine nuclei NYATA: mengeksekusi binary nuclei sebagai
// subprocess lalu menormalkan output JSONL-nya lewat Parse.
//
// Koneksi keluar wajib lewat proxy egress bughound — orchestrator memanggil
// UseProxy sebelum Scan sehingga setiap request nuclei diperiksa scope guard
// SEBELUM koneksi dibuat (internal/egress). Runner ini bukan default; aktifkan
// secara sadar dan hanya terhadap target yang sah (lihat CLAUDE.md: jangan
// menjalankan scan nyata di lingkungan dev/test).
type Runner struct {
	Binary    string // default "nuclei"
	RateLimit int    // -rate-limit (req/dtk); 0 = default nuclei
	proxyAddr string
}

// Name memenuhi engine.Engine.
func (r *Runner) Name() string { return "nuclei" }

// UseProxy memenuhi engine.ProxyAware: mengarahkan nuclei ke proxy egress.
func (r *Runner) UseProxy(addr string) { r.proxyAddr = addr }

// Scan memenuhi engine.Engine.
func (r *Runner) Scan(ctx context.Context, target, program, runID string) ([]*finding.Finding, error) {
	bin := r.Binary
	if bin == "" {
		bin = "nuclei"
	}
	cmd := exec.CommandContext(ctx, bin, r.buildArgs(target)...)
	if r.proxyAddr != "" {
		cmd.Env = egress.ProxyEnv(os.Environ(), "http://"+r.proxyAddr) // belt-and-suspenders
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("nuclei: eksekusi gagal: %w (%s)", err, stderr.String())
	}
	return Parse(&stdout, program, runID)
}

func (r *Runner) buildArgs(target string) []string {
	args := []string{"-jsonl", "-silent", "-disable-update-check", "-target", target}
	if r.proxyAddr != "" {
		args = append(args, "-proxy", "http://"+r.proxyAddr)
	}
	if r.RateLimit > 0 {
		args = append(args, "-rate-limit", strconv.Itoa(r.RateLimit))
	}
	return args
}
