package zap

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"bughound/internal/finding"
)

// Runner adalah engine ZAP NYATA. Dua mode:
//   - "quick"/"baseline" (default): quickscan `zap.sh -cmd -quickurl` (spider +
//     pasif), cepat & ringan.
//   - "full": Automation Framework (`-autorun plan.yaml`) dengan spider +
//     activeScan + laporan JSON — cakupan lebih dalam (aktif menyerang), lebih lama.
//
// Bukan default; butuh OWASP ZAP terpasang. Bila UseProxy diset, koneksi ZAP
// diarahkan ke proxy egress bughound lewat config upstream proxy (scope guard
// per koneksi). Invokasi ZAP berat (JVM) & belum dijalankan di lingkungan ini;
// args/plan & Parse diuji, eksekusi nyata dipakai sadar untuk target sah.
type Runner struct {
	Binary    string // default "zap.sh"
	Mode      string // "quick" (default) | "baseline" | "full"
	proxyAddr string
}

// Name memenuhi engine.Engine.
func (r *Runner) Name() string { return "zap" }

// UseProxy memenuhi engine.ProxyAware.
func (r *Runner) UseProxy(addr string) { r.proxyAddr = addr }

func (r *Runner) mode() string {
	switch strings.ToLower(strings.TrimSpace(r.Mode)) {
	case "full":
		return "full"
	case "baseline":
		return "baseline"
	default:
		return "quick"
	}
}

// Scan memenuhi engine.Engine.
func (r *Runner) Scan(ctx context.Context, target, program, runID string) ([]*finding.Finding, error) {
	bin := r.Binary
	if bin == "" {
		bin = "zap.sh"
	}
	if r.mode() == "full" {
		return r.scanFull(ctx, bin, target, program, runID)
	}
	return r.scanQuick(ctx, bin, target, program, runID)
}

// scanQuick: quickscan menulis laporan JSON ke berkas, lalu Parse.
func (r *Runner) scanQuick(ctx context.Context, bin, target, program, runID string) ([]*finding.Finding, error) {
	tmp, err := os.CreateTemp("", "zap-*.json")
	if err != nil {
		return nil, fmt.Errorf("zap: berkas sementara: %w", err)
	}
	out := tmp.Name()
	tmp.Close()
	defer os.Remove(out)

	if err := r.run(ctx, bin, r.buildArgs(target, out)); err != nil {
		return nil, err
	}
	return readReport(out, program, runID)
}

// scanFull: Automation Framework (spider + activeScan + report JSON), lalu Parse.
func (r *Runner) scanFull(ctx context.Context, bin, target, program, runID string) ([]*finding.Finding, error) {
	dir, err := os.MkdirTemp("", "zap-full-*")
	if err != nil {
		return nil, fmt.Errorf("zap: dir sementara: %w", err)
	}
	defer os.RemoveAll(dir)

	const reportFile = "report.json"
	planPath := filepath.Join(dir, "plan.yaml")
	if err := os.WriteFile(planPath, []byte(planYAML(target, dir, reportFile)), 0o600); err != nil {
		return nil, fmt.Errorf("zap: tulis plan: %w", err)
	}
	if err := r.run(ctx, bin, r.buildFullArgs(planPath)); err != nil {
		return nil, err
	}
	return readReport(filepath.Join(dir, reportFile), program, runID)
}

func (r *Runner) run(ctx context.Context, bin string, args []string) error {
	cmd := exec.CommandContext(ctx, bin, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("zap: eksekusi gagal: %w (%s)", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func readReport(path, program, runID string) ([]*finding.Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("zap: baca laporan: %w", err)
	}
	return Parse(bytes.NewReader(data), program, runID)
}

func (r *Runner) buildArgs(target, out string) []string {
	args := []string{"-cmd", "-quickurl", target, "-quickout", out, "-quickprogress"}
	return append(args, r.proxyConfigArgs()...)
}

func (r *Runner) buildFullArgs(planPath string) []string {
	return append([]string{"-cmd", "-autorun", planPath}, r.proxyConfigArgs()...)
}

// proxyConfigArgs mengarahkan ZAP ke proxy egress bughound (bila diset).
func (r *Runner) proxyConfigArgs() []string {
	if r.proxyAddr == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(r.proxyAddr)
	if err != nil {
		return nil
	}
	return []string{
		"-config", "network.connection.httpProxy.host=" + host,
		"-config", "network.connection.httpProxy.port=" + port,
		"-config", "network.connection.httpProxy.enabled=true",
	}
}

// planYAML menyusun rencana ZAP Automation Framework: spider → activeScan →
// laporan traditional-json.
func planYAML(target, reportDir, reportFile string) string {
	return "" +
		"env:\n" +
		"  contexts:\n" +
		"    - name: bughound\n" +
		"      urls: [\"" + target + "\"]\n" +
		"  parameters:\n" +
		"    failOnError: false\n" +
		"jobs:\n" +
		"  - type: spider\n" +
		"    parameters:\n" +
		"      context: bughound\n" +
		"      url: \"" + target + "\"\n" +
		"  - type: activeScan\n" +
		"    parameters:\n" +
		"      context: bughound\n" +
		"  - type: report\n" +
		"    parameters:\n" +
		"      template: traditional-json\n" +
		"      reportDir: \"" + reportDir + "\"\n" +
		"      reportFile: \"" + reportFile + "\"\n"
}
