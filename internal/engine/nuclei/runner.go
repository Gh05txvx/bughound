package nuclei

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
	// Tags & Severity menyeleksi SUBSET template yang dijalankan (dari metadata
	// bank payload, BH-SPEC-PAYLOAD §Seleksi). Kosong = jalankan semua template
	// terpasang. -tags dan -severity dikombinasikan (template harus cocok
	// keduanya), memangkas 14k template ke subset terarah → scan jauh lebih cepat.
	Tags     []string // -tags t1,t2
	Severity []string // -severity critical,high
	// TemplatesDir (opsional) membatasi nuclei HANYA ke direktori template ini
	// via `-t` — dipakai runner "custom" khusus Bank Payload (BH-SPEC-PAYLOAD):
	// menjalankan template deteksi read-only milik sendiri, TERPISAH dari runner
	// utama yang menjalankan set resmi penuh. Kosong = set template bawaan nuclei.
	TemplatesDir string
	proxyAddr    string
	authHeaders  []string // Lever 1: header auth disuntik via -H (lihat UseAuthHeaders)
}

// Name memenuhi engine.Engine. Runner ber-TemplatesDir dilabeli "nuclei-custom"
// agar roster/log membedakannya dari runner nuclei resmi.
func (r *Runner) Name() string {
	if strings.TrimSpace(r.TemplatesDir) != "" {
		return "nuclei-custom"
	}
	return "nuclei"
}

// UseProxy memenuhi engine.ProxyAware: mengarahkan nuclei ke proxy egress.
func (r *Runner) UseProxy(addr string) { r.proxyAddr = addr }

// UseAuthHeaders memenuhi engine.AuthAware: menyuntik header auth (-H) ke tiap
// request nuclei agar scan menjangkau konten di balik login (Lever 1).
func (r *Runner) UseAuthHeaders(h []string) { r.authHeaders = h }

// headerArgs merender header auth menjadi argumen `-H "Nama: nilai"` (dipakai
// runner nuclei biasa & -dast). Nilai diteruskan apa adanya ke argv (tanpa
// shell), jadi spasi/`;` di cookie aman.
func headerArgs(headers []string) []string {
	a := make([]string, 0, 2*len(headers))
	for _, h := range headers {
		if strings.TrimSpace(h) != "" {
			a = append(a, "-H", h)
		}
	}
	return a
}

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
	if dir := strings.TrimSpace(r.TemplatesDir); dir != "" {
		// Batasi HANYA ke template custom (runner khusus Bank Payload). nuclei
		// tetap menerapkan -tags/-severity & argumen non-destruktif di bawah.
		args = append(args, "-t", dir)
	}
	if r.proxyAddr != "" {
		args = append(args, "-proxy", "http://"+r.proxyAddr)
	}
	if r.RateLimit > 0 {
		args = append(args, "-rate-limit", strconv.Itoa(r.RateLimit))
	}
	if tags := joinNonEmpty(r.Tags); tags != "" {
		args = append(args, "-tags", tags)
	}
	if sev := joinNonEmpty(r.Severity); sev != "" {
		args = append(args, "-severity", sev)
	}
	args = append(args, headerArgs(r.authHeaders)...) // Lever 1: header auth (bila ada)
	// Non-destruktif struktural: berlaku juga di plain runner, bukan hanya -dast.
	// Tanpa ini, template unsafe destruktif (smuggling, unggah webshell) ikut jalan.
	args = append(args, nonDestructiveArgs()...)
	return args
}

// joinNonEmpty menggabungkan nilai ter-trim non-kosong dengan koma (format daftar
// yang diterima flag -tags/-severity nuclei); mengembalikan "" bila tak ada.
func joinNonEmpty(in []string) string {
	var out []string
	for _, v := range in {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return strings.Join(out, ",")
}
