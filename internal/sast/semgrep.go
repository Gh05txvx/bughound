package sast

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"bughound/internal/finding"
)

// Runner adalah adapter SAST nyata: menjalankan `semgrep --json` sebagai
// subprocess lalu menormalkan hasilnya (Parse). OPT-IN — butuh binary semgrep
// terpasang; tak pernah dijalankan terhadap kode di luar root (dijamin Resolve
// di jalur eksekusi).
//
// Config default `p/default` (ruleset registry semgrep). `auto` sengaja TIDAK
// dipakai: ia menolak berjalan saat metrik dimatikan ("Cannot create auto
// config when metrics are off"), dan kami memilih `--metrics=off` agar tak
// mengirim telemetri soal kode yang dipindai. Ruleset registry diunduh sekali
// lalu di-cache; untuk mode offline/kustom, set field Config atau env
// BUGHOUND_SEMGREP_CONFIG ke path ruleset lokal.
type Runner struct {
	Bin    string // default "semgrep"
	Config string // default "p/default" (lihat config())
}

// Name memenuhi Engine.
func (r *Runner) Name() string { return "semgrep" }

// config memilih ruleset: field Config bila diisi, lalu env
// BUGHOUND_SEMGREP_CONFIG, lalu default `p/default`. `auto` sengaja bukan
// default karena tak kompatibel dengan --metrics=off.
func (r *Runner) config() string {
	if strings.TrimSpace(r.Config) != "" {
		return r.Config
	}
	if c := strings.TrimSpace(os.Getenv("BUGHOUND_SEMGREP_CONFIG")); c != "" {
		return c
	}
	return "p/default"
}

// args menyusun argumen semgrep (dipisah agar bisa diuji tanpa mengeksekusi).
func (r *Runner) args(dir string) []string {
	return []string{"--json", "--quiet", "--metrics=off", "--config", r.config(), dir}
}

// Analyze menjalankan semgrep pada dir dan mengembalikan temuan ternormalkan.
func (r *Runner) Analyze(ctx context.Context, dir, _, _ string) ([]*finding.Finding, error) {
	bin := r.Bin
	if bin == "" {
		bin = "semgrep"
	}
	cmd := exec.CommandContext(ctx, bin, r.args(dir)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			// semgrep: exit 1 = ada temuan (normal); >1 = error nyata.
			if ee.ExitCode() > 1 {
				return nil, fmt.Errorf("semgrep: %v: %s", err, strings.TrimSpace(stderr.String()))
			}
		} else {
			return nil, fmt.Errorf("semgrep: %w", err)
		}
	}
	return Parse(bytes.NewReader(stdout.Bytes()))
}

type semgrepOutput struct {
	Results []semgrepResult `json:"results"`
}

type semgrepResult struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   struct {
		Line int `json:"line"`
	} `json:"start"`
	Extra struct {
		Message  string `json:"message"`
		Severity string `json:"severity"`
		Lines    string `json:"lines"`
		Metadata struct {
			CWE        []string `json:"cwe"`
			References []string `json:"references"`
			Confidence string   `json:"confidence"`
		} `json:"metadata"`
	} `json:"extra"`
}

// Parse menormalkan output JSON semgrep ke Skema Temuan Seragam. program/run_id/
// target diisi oleh Run. Tak menyentuh jaringan.
func Parse(r io.Reader) ([]*finding.Finding, error) {
	var out semgrepOutput
	if err := json.NewDecoder(r).Decode(&out); err != nil {
		return nil, fmt.Errorf("semgrep: decode json: %w", err)
	}
	var fs []*finding.Finding
	for _, res := range out.Results {
		loc := res.Path
		if res.Start.Line > 0 {
			loc = fmt.Sprintf("%s:%d", res.Path, res.Start.Line)
		}
		title := strings.TrimSpace(res.Extra.Message)
		if title == "" {
			title = res.CheckID
		}
		f := &finding.Finding{
			Type:           res.CheckID,
			Title:          truncate(title, 160),
			Description:    strings.TrimSpace(res.Extra.Message),
			Severity:       mapSemgrepSeverity(res.Extra.Severity),
			Confidence:     mapSemgrepConfidence(res.Extra.Metadata.Confidence),
			Status:         finding.StatusNew,
			SourceEngine:   "semgrep",
			SourceTemplate: res.CheckID,
			CWE:            normalizeCWE(res.Extra.Metadata.CWE),
			References:     res.Extra.Metadata.References,
			Location:       finding.Location{URL: loc},
		}
		if m := strings.TrimSpace(res.Extra.Lines); m != "" {
			f.Evidence = &finding.Evidence{Matched: m}
		}
		fs = append(fs, f)
	}
	return fs, nil
}

func mapSemgrepSeverity(s string) finding.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "ERROR":
		return finding.SeverityHigh
	case "WARNING":
		return finding.SeverityMedium
	case "INFO":
		return finding.SeverityInfo
	default:
		return finding.SeverityLow
	}
}

func mapSemgrepConfidence(s string) finding.Confidence {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "HIGH":
		return finding.ConfidenceHigh
	case "LOW":
		return finding.ConfidenceLow
	default:
		return finding.ConfidenceMedium
	}
}

// normalizeCWE mengambil kode "CWE-###" dari entri seperti "CWE-798: Use of ...".
func normalizeCWE(in []string) []string {
	var out []string
	for _, c := range in {
		code := strings.TrimSpace(c)
		if i := strings.IndexByte(code, ':'); i > 0 {
			code = strings.TrimSpace(code[:i])
		}
		if code != "" {
			out = append(out, code)
		}
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// sampleSemgrepJSON adalah output semgrep terekam untuk uji Parse (tanpa biner).
const sampleSemgrepJSON = `{
  "results": [
    {
      "check_id": "generic.secrets.security.detected-generic-secret",
      "path": "internal/config/db.go",
      "start": {"line": 14, "col": 2},
      "end": {"line": 14, "col": 40},
      "extra": {
        "message": "Hardcoded secret detected",
        "severity": "ERROR",
        "lines": "  dbPassword := \"s3cr3t-do-not-commit\"",
        "metadata": {"cwe": ["CWE-798: Use of Hard-coded Credentials"], "confidence": "HIGH", "references": ["https://owasp.org/"]}
      }
    },
    {
      "check_id": "go.lang.security.audit.crypto.insecure-random",
      "path": "internal/token/token.go",
      "start": {"line": 8, "col": 11},
      "end": {"line": 8, "col": 30},
      "extra": {
        "message": "Use crypto/rand instead of math/rand for security-sensitive values",
        "severity": "WARNING",
        "lines": "  token := rand.Intn(1000000)",
        "metadata": {"cwe": ["CWE-338"], "confidence": "MEDIUM"}
      }
    }
  ],
  "errors": []
}`

func init() { Register("semgrep", func() Engine { return &Runner{} }) }
