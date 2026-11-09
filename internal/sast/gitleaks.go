package sast

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"

	"bughound/internal/finding"
)

// GitleaksRunner adalah adapter SAST untuk Gitleaks (deteksi secret ter-commit:
// API key, token, kredensial). Menjalankan `gitleaks detect` dengan keluaran
// SARIF lalu menormalkannya lewat NormalizeSARIF bersama.
//
// KEAMANAN (Prinsip #5 — secret tak pernah bocor): redaksi berlapis. (1) gitleaks
// dijalankan dengan `--redact` sehingga nilai secret sudah disensor di sumber;
// (2) NormalizeSARIF diberi redactSecret sebagai jaring pengaman yang menutup
// token panjang bila ada yang lolos. Cuplikan yang tersimpan menampilkan konteks
// (mis. nama variabel) tanpa nilai secret.
//
// OPT-IN: butuh biner `gitleaks`. Tak menyentuh jaringan; dikurung ke dir in-scope.
type GitleaksRunner struct {
	Bin string // default "gitleaks"
}

// Name memenuhi Engine.
func (r *GitleaksRunner) Name() string { return "gitleaks" }

// args menyusun argumen gitleaks. report ditulis ke berkas (SARIF), bukan stdout.
// --no-git: pindai berkas apa adanya (target boleh bukan repo git). --redact:
// sensor nilai secret di sumber. --exit-code 0: temuan bukan kondisi error (kita
// ukur sukses dari laporan yang bisa diurai). --no-banner: tanpa ASCII art.
func (r *GitleaksRunner) args(dir, report string) []string {
	return []string{
		"detect", "--source", dir, "--no-git",
		"--report-format", "sarif", "--report-path", report,
		"--redact", "--exit-code", "0", "--no-banner",
	}
}

// Analyze menjalankan gitleaks pada dir dan mengembalikan temuan ternormalkan.
func (r *GitleaksRunner) Analyze(ctx context.Context, dir, _, _ string) ([]*finding.Finding, error) {
	bin := r.Bin
	if bin == "" {
		bin = "gitleaks"
	}
	tmp, err := os.CreateTemp("", "gitleaks-*.sarif")
	if err != nil {
		return nil, fmt.Errorf("gitleaks: temp: %w", err)
	}
	report := tmp.Name()
	tmp.Close()
	defer os.Remove(report)

	cmd := exec.CommandContext(ctx, bin, r.args(dir, report)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	data, rerr := os.ReadFile(report)
	if rerr != nil || len(bytes.TrimSpace(data)) == 0 {
		// Tak ada laporan terbaca → bila proses gagal, itu error sungguhan.
		if runErr != nil {
			return nil, fmt.Errorf("gitleaks: %v: %s", runErr, strings.TrimSpace(stderr.String()))
		}
		// Proses sukses tapi laporan kosong = tak ada temuan (gitleaks bisa tak
		// menulis berkas saat nol leak pada sebagian versi).
		return nil, nil
	}
	return parseGitleaks(data)
}

// parseGitleaks menormalkan SARIF gitleaks + melengkapi metadata khusus secret:
// CWE-798 (hardcoded credentials) default bila kosong, dan tag "secret".
func parseGitleaks(data []byte) ([]*finding.Finding, error) {
	fs, err := NormalizeSARIF(data, "gitleaks", redactSecret)
	if err != nil {
		return nil, err
	}
	for _, f := range fs {
		if len(f.CWE) == 0 {
			f.CWE = []string{"CWE-798"} // Use of Hard-coded Credentials
		}
		f.Tags = ensureTag(f.Tags, "secret")
	}
	return fs, nil
}

// redactSecret adalah jaring pengaman: menutup token panjang menyerupai secret
// (deret >= 20 char base64/hex/url-safe) menjadi prefix + penanda, menjaga
// konteks tetap berguna tanpa membocorkan nilai. Dipakai di atas `--redact`
// gitleaks sebagai lapis kedua.
func redactSecret(s string) string {
	var b strings.Builder
	runStart := -1
	flush := func(end int) {
		if runStart < 0 {
			return
		}
		run := s[runStart:end]
		if len(run) >= 20 {
			b.WriteString(run[:4])
			b.WriteString("…[REDACTED]")
		} else {
			b.WriteString(run)
		}
		runStart = -1
	}
	for i := 0; i < len(s); i++ {
		if isSecretChar(s[i]) {
			if runStart < 0 {
				runStart = i
			}
			continue
		}
		flush(i)
		b.WriteByte(s[i])
	}
	flush(len(s))
	return b.String()
}

func isSecretChar(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
		c == '+' || c == '/' || c == '=' || c == '_' || c == '-'
}

// ensureTag menambahkan tag bila belum ada.
func ensureTag(tags []string, tag string) []string {
	if slices.Contains(tags, tag) {
		return tags
	}
	return append(tags, tag)
}

func init() { Register("gitleaks", func() Engine { return &GitleaksRunner{} }) }
