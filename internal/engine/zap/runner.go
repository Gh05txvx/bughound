package zap

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"bughound/internal/engine"
	"bughound/internal/finding"
)

// Runner adalah engine ZAP NYATA. Dua mode, KEDUANYA lewat ZAP Automation
// Framework (plan YAML → laporan traditional-json):
//   - "quick"/"baseline" (default): spider + PASSIVE scan, TANPA active scan.
//     Tidak mengirim payload serangan (setara zap-baseline): hanya aturan pasif
//     (header hilang, versi/informasi bocor, berkas tersingkap). Aman & ringan.
//   - "full": spider + ACTIVE scan (mengirim payload: SQLi/XSS/dst.) + laporan.
//     Cakupan lebih dalam, lebih lama, dan AKTIF MENYERANG — hanya saat
//     startup `-zap-mode full`.
//
// Bukan default; butuh OWASP ZAP terpasang. Bila UseProxy diset, koneksi ZAP
// diarahkan ke proxy egress bughound lewat config upstream proxy (scope guard
// per koneksi). Invokasi ZAP berat (JVM); args/plan & Parse diuji, eksekusi nyata
// dipakai sadar untuk target sah.
type Runner struct {
	Binary      string // default "zap.sh"
	Mode        string // "quick" (default) | "baseline" | "full"
	RateLimit   int    // throttle active scan: 0 = default ZAP; >0 = 1 thread/host + jeda ~1000/rate ms
	proxyAddr   string
	authHeaders []string // Lever 1: header auth → aturan Replacer di plan (lihat UseAuthHeaders)
}

// Name memenuhi engine.Engine.
func (r *Runner) Name() string { return "zap" }

// UseProxy memenuhi engine.ProxyAware.
func (r *Runner) UseProxy(addr string) { r.proxyAddr = addr }

// UseAuthHeaders memenuhi engine.AuthAware: tiap header "Nama: nilai" menjadi
// aturan Replacer di plan, sehingga SETIAP request ZAP (spider, passive, active)
// membawa sesi login (Lever 1). Nilai = secret: hanya tertulis ke plan (0600) &
// home ZAP per run (config.xml, zap.log) — keduanya di dir sementara 0700 yang
// dihapus selepas run (lihat buildPlanArgs).
func (r *Runner) UseAuthHeaders(h []string) { r.authHeaders = h }

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

// active menandai mode yang mengirim payload serangan (active scan). HANYA "full".
// quick/baseline sengaja pasif agar default aman untuk target bug bounty.
func (r *Runner) active() bool { return r.mode() == "full" }

// Scan memenuhi engine.Engine.
func (r *Runner) Scan(ctx context.Context, target, program, runID string) ([]*finding.Finding, error) {
	bin := r.Binary
	if bin == "" {
		bin = "zap.sh"
	}
	return r.scanPlan(ctx, bin, target, program, runID, r.active())
}

// scanPlan menulis plan Automation Framework (spider + passive, atau + active bila
// full), menjalankan ZAP, lalu Parse laporan JSON. active=false TAK mengirim
// payload serangan apa pun.
func (r *Runner) scanPlan(ctx context.Context, bin, target, program, runID string, active bool) ([]*finding.Finding, error) {
	dir, err := os.MkdirTemp("", "zap-*")
	if err != nil {
		return nil, fmt.Errorf("zap: dir sementara: %w", err)
	}
	defer os.RemoveAll(dir)

	const reportFile = "report.json"
	planPath := filepath.Join(dir, "plan.yaml")
	if err := os.WriteFile(planPath, []byte(planYAML(target, dir, reportFile, active, r.authHeaders)), 0o600); err != nil {
		return nil, fmt.Errorf("zap: tulis plan: %w", err)
	}
	if err := r.run(ctx, bin, r.buildPlanArgs(planPath, dir)); err != nil {
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

// buildPlanArgs: -dir menjadikan homeDir (dir sementara per run, dihapus selepas
// run) sebagai home ZAP. ZAP menyimpan opsi run ke home-nya — termasuk aturan
// Replacer berisi NILAI header auth (config.xml, zap.log, sesi). Home bersama
// (~/.ZAP) membuat sesi satu program ikut terkirim ke scan berikutnya (program
// lain) & tertinggal di disk — terbukti live 2026-11-16.
func (r *Runner) buildPlanArgs(planPath, homeDir string) []string {
	args := append([]string{"-cmd", "-dir", homeDir, "-autorun", planPath}, r.proxyConfigArgs()...)
	return append(args, r.throttleArgs()...)
}

// throttleArgs menjepit keagresifan active scanner ZAP ke target (RateLimit
// req/dtk): satu thread per host + jeda antar-request ~1000/rate ms. Hanya
// berpengaruh pada mode full (active scan); di quick/baseline (pasif) ini no-op —
// laju request pasif tetap dijepit oleh rate limiter di proxy egress bughound.
func (r *Runner) throttleArgs() []string {
	if r.RateLimit <= 0 {
		return nil
	}
	delayMs := 1000 / r.RateLimit
	if delayMs < 1 {
		delayMs = 1
	}
	return []string{
		"-config", "scanner.threadPerHost=1",
		"-config", "scanner.delayInMs=" + strconv.Itoa(delayMs),
	}
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

// Batas waktu plan (menit). Active scan tanpa batas bisa berjalan berjam-jam dan
// membanjiri target — terutama di SPA catch-all yang permukaan spider-nya hampir
// tak-hingga. Batas ini menjaga scan tetap tuntas & tak menumbangkan target;
// throttle per-request (throttleArgs) tetap di jalur terpisah.
const (
	spiderMaxDurationMin      = 3  // spider berhenti setelah 3 menit
	passiveWaitMaxDurationMin = 5  // tunggu antrean passive scan kosong maksimal 5 menit
	ascanMaxDurationMin       = 10 // total active scan maksimal 10 menit (mode full)
	ascanMaxRuleDurMin        = 2  // tiap rule active scan maksimal 2 menit (mode full)
)

// planYAML menyusun rencana ZAP Automation Framework. Selalu: spider → (job scan) →
// laporan traditional-json. Job scan tergantung active:
//   - active=false (quick/baseline): passiveScan-wait — tunggu aturan PASIF tuntas,
//     tanpa mengirim satu pun payload serangan.
//   - active=true (full): activeScan — kirim payload (SQLi/XSS/dst.).
//
// Spider & activeScan dibatasi durasinya (lihat konstanta) agar tuntas di host
// kecil dan tak membanjiri target. Bila ada header auth, job replacer (lihat
// replacerJob) dipasang paling depan dan route logout dikeluarkan dari context.
func planYAML(target, reportDir, reportFile string, active bool, authHeaders []string) string {
	replacer, excl := replacerJob(authHeaders), ""
	if replacer != "" {
		// Spider ZAP mengikuti link logout (live 2026-11-16) → sesi mati & sisa scan
		// diam-diam tanpa login. URL di luar context tak di-spider/scan.
		excl = "      excludePaths:\n        - " + strconv.Quote(engine.LogoutPattern) + "\n"
	}
	plan := "" +
		"env:\n" +
		"  contexts:\n" +
		"    - name: bughound\n" +
		"      urls: [\"" + target + "\"]\n" +
		excl +
		"  parameters:\n" +
		"    failOnError: false\n" +
		"jobs:\n" +
		replacer +
		"  - type: spider\n" +
		"    parameters:\n" +
		"      context: bughound\n" +
		"      url: \"" + target + "\"\n" +
		"      maxDuration: " + strconv.Itoa(spiderMaxDurationMin) + "\n"
	if active {
		plan += "" +
			"  - type: activeScan\n" +
			"    parameters:\n" +
			"      context: bughound\n" +
			"      maxScanDurationInMins: " + strconv.Itoa(ascanMaxDurationMin) + "\n" +
			"      maxRuleDurationInMins: " + strconv.Itoa(ascanMaxRuleDurMin) + "\n"
	} else {
		plan += "" +
			"  - type: passiveScan-wait\n" +
			"    parameters:\n" +
			"      maxDuration: " + strconv.Itoa(passiveWaitMaxDurationMin) + "\n"
	}
	return plan + "" +
		"  - type: report\n" +
		"    parameters:\n" +
		"      template: traditional-json\n" +
		"      reportDir: \"" + reportDir + "\"\n" +
		"      reportFile: \"" + reportFile + "\"\n"
}

// replacerJob merender header auth (Lever 1) menjadi job Replacer ZAP. Dipasang
// SEBELUM spider agar semua job sesudahnya membawa header. matchType req_header:
// header ditambah bila absen, ditimpa bila ada. url & initiators kosong = semua
// request ZAP; batasnya tetap scope guard di egress, sama seperti `-H` engine lain.
// Nama & nilai di-quote strconv.Quote (escape Go ⊂ escape double-quoted YAML), jadi
// cookie berisi `"`/`#`/`:` tak bisa merusak atau menyusupi plan. Tanpa header sah
// → "" (plan tak berubah).
func replacerJob(headers []string) string {
	var rules strings.Builder
	n := 0
	for _, h := range headers {
		name, val, ok := strings.Cut(h, ":")
		name, val = strings.TrimSpace(name), strings.TrimSpace(val)
		if !ok || name == "" || val == "" {
			continue // baris rusak dilewati; nilai kosong malah MENGHAPUS header di Replacer
		}
		n++
		fmt.Fprintf(&rules, "      - description: \"bughound-auth-%d\"\n"+
			"        matchType: req_header\n"+
			"        matchString: %s\n"+
			"        matchRegex: false\n"+
			"        replacementString: %s\n", n, strconv.Quote(name), strconv.Quote(val))
	}
	if n == 0 {
		return ""
	}
	return "  - type: replacer\n    rules:\n" + rules.String()
}
