package zap

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"bughound/internal/finding"
)

// Runner adalah engine ZAP NYATA: menjalankan quickscan (`zap.sh -cmd -quickurl`)
// yang menulis laporan JSON, lalu menormalkannya lewat Parse. Bukan default;
// butuh OWASP ZAP terpasang. Bila UseProxy diset, koneksi ZAP diarahkan ke
// proxy egress bughound lewat config upstream proxy (scope guard per koneksi).
//
// Catatan: invokasi ZAP berat (JVM) dan belum dijalankan di lingkungan ini;
// args & Parse diuji, eksekusi nyata dipakai secara sadar untuk target sah.
type Runner struct {
	Binary    string // default "zap.sh"
	proxyAddr string
}

// Name memenuhi engine.Engine.
func (r *Runner) Name() string { return "zap" }

// UseProxy memenuhi engine.ProxyAware.
func (r *Runner) UseProxy(addr string) { r.proxyAddr = addr }

// Scan memenuhi engine.Engine.
func (r *Runner) Scan(ctx context.Context, target, program, runID string) ([]*finding.Finding, error) {
	bin := r.Binary
	if bin == "" {
		bin = "zap.sh"
	}
	tmp, err := os.CreateTemp("", "zap-*.json")
	if err != nil {
		return nil, fmt.Errorf("zap: berkas sementara: %w", err)
	}
	out := tmp.Name()
	tmp.Close()
	defer os.Remove(out)

	cmd := exec.CommandContext(ctx, bin, r.buildArgs(target, out)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("zap: eksekusi gagal: %w (%s)", err, strings.TrimSpace(stderr.String()))
	}
	data, err := os.ReadFile(out)
	if err != nil {
		return nil, fmt.Errorf("zap: baca laporan: %w", err)
	}
	return Parse(bytes.NewReader(data), program, runID)
}

func (r *Runner) buildArgs(target, out string) []string {
	args := []string{"-cmd", "-quickurl", target, "-quickout", out, "-quickprogress"}
	if r.proxyAddr != "" {
		host, port, err := net.SplitHostPort(r.proxyAddr)
		if err == nil {
			args = append(args,
				"-config", "network.connection.httpProxy.host="+host,
				"-config", "network.connection.httpProxy.port="+port,
				"-config", "network.connection.httpProxy.enabled=true",
			)
		}
	}
	return args
}
