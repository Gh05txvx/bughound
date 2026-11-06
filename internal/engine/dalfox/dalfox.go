// Package dalfox membungkus dalfox (hahwul/dalfox) sebagai engine DAST AKTIF
// khusus XSS di balik kontrak engine seragam. Ia mengirim payload XSS ke
// parameter target lalu menormalkan PoC yang ditemukan ke Skema Temuan Seragam
// (BH-SPEC-FINDING), seperti engine lain.
//
// Keamanan (area sensitif): SEMUA request lewat proxy egress scope-enforced —
// dalfox dijalankan dengan --proxy menunjuk proxy bughound, sehingga tiap
// koneksi keluar diperiksa scope guard (payload hanya mengubah NILAI parameter;
// host tetap in-scope; blind/OAST ke pihak-3 diblok proxy). Fail-safe: tanpa
// proxy, TIDAK ada koneksi apa pun. Volume dibatasi worker + delay (stealth).
// Non-destruktif: dalfox menguji refleksi/eksekusi XSS, tak melakukan aksi
// merusak. Temuan = KANDIDAT (draft→verify manual), selaras filosofi bughound.
package dalfox

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

// Runner adalah adapter dalfox nyata (OPT-IN; butuh binary dalfox di PATH).
type Runner struct {
	Binary    string // default "dalfox"
	RateLimit int    // perkiraan laju → dipetakan ke --delay (ms) bila > 0
	Stealth   bool   // low-and-slow: worker lebih sedikit + delay
	proxyAddr string
}

// Name memenuhi engine.Engine.
func (r *Runner) Name() string { return "dalfox" }

// UseProxy memenuhi engine.ProxyAware: seluruh request dalfox lewat proxy egress.
func (r *Runner) UseProxy(addr string) { r.proxyAddr = addr }

// Scan memenuhi engine.Engine: jalankan dalfox atas target lalu normalkan PoC.
func (r *Runner) Scan(ctx context.Context, target, program, runID string) ([]*finding.Finding, error) {
	// Fail-safe: tanpa proxy egress, JANGAN buat koneksi apa pun (selaras prinsip
	// "tidak pernah memicu koneksi yang memintas scope guard").
	if r.proxyAddr == "" {
		return nil, nil
	}

	outFile, err := os.CreateTemp("", "dalfox-*.json")
	if err != nil {
		return nil, fmt.Errorf("dalfox: berkas output: %w", err)
	}
	outPath := outFile.Name()
	_ = outFile.Close()
	defer os.Remove(outPath)

	bin := r.Binary
	if bin == "" {
		bin = "dalfox"
	}
	cmd := exec.CommandContext(ctx, bin, r.args(target, outPath)...)
	cmd.Env = egress.ProxyEnv(os.Environ(), "http://"+r.proxyAddr) // belt-and-suspenders
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	// Baca hasil dari berkas output lebih dulu: dalfox menulis PoC ke sana
	// terlepas dari kode keluar. Bila ada temuan, kembalikan meski exit non-zero
	// (toleran pada kuirk exit dalfox); bila kosong & ada error, laporkan error.
	data, _ := os.ReadFile(outPath)
	fs, perr := Parse(bytes.NewReader(data), target, program, runID)
	if perr != nil {
		if runErr != nil {
			return nil, fmt.Errorf("dalfox: eksekusi gagal: %w (%s)", runErr, strings.TrimSpace(stderr.String()))
		}
		return nil, fmt.Errorf("dalfox: parse: %w", perr)
	}
	if len(fs) == 0 && runErr != nil {
		return nil, fmt.Errorf("dalfox: eksekusi gagal: %w (%s)", runErr, strings.TrimSpace(stderr.String()))
	}
	return fs, nil
}

// args menyusun argumen dalfox (dipisah agar bisa diuji tanpa mengeksekusi).
// Output JSON ditulis ke berkas (parse bersih, lepas dari noise stdout); seluruh
// request diarahkan ke proxy egress; worker/delay membatasi volume.
func (r *Runner) args(target, outPath string) []string {
	a := []string{
		"url", target,
		"--format", "json",
		"--output", outPath,
		"--output-request",  // sertakan HTTP request mentah → Evidence.Request (siap-Burp)
		"--output-response", // sertakan HTTP response mentah → Evidence.ResponseExcerpt
		"--silence",
		"--no-spinner",
		"--no-color",
		"--proxy", "http://" + r.proxyAddr,
		"--timeout", "10",
		"--worker", strconv.Itoa(r.workers()),
	}
	if d := r.delayMS(); d > 0 {
		a = append(a, "--delay", strconv.Itoa(d))
	}
	return a
}

// workers menentukan konkruensi dalfox: lebih rendah saat stealth (jejak minimal).
func (r *Runner) workers() int {
	if r.Stealth {
		return 10
	}
	return 40
}

// delayMS menentukan jeda antar-request (ms): dari RateLimit bila diset, lalu
// jeda stealth bawaan, selain itu 0 (tanpa jeda tambahan).
func (r *Runner) delayMS() int {
	if r.RateLimit > 0 {
		ms := 1000 / r.RateLimit
		if ms < 1 {
			ms = 1
		}
		return ms
	}
	if r.Stealth {
		return 200
	}
	return 0
}
