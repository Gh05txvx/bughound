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

// Runner is a real SAST adapter: it runs `semgrep --json` as a subprocess and
// normalizes the result (Parse). OPT-IN: needs the semgrep binary installed; it
// never runs against code outside the root (Resolve guarantees that in the
// execution path).
//
// The default config is `p/default` (a semgrep registry ruleset). `auto` is
// deliberately NOT used: it refuses to run when metrics are off ("Cannot
// create auto config when metrics are off"), and we chose `--metrics=off` so no
// telemetry about the scanned code is sent. The registry ruleset is downloaded
// once and then cached; for offline/custom mode, set the Config field or env
// BUGHOUND_SEMGREP_CONFIG to a local ruleset path.
type Runner struct {
	Bin    string // default "semgrep"
	Config string // default "p/default" (see config())
}

// Name implements Engine.
func (r *Runner) Name() string { return "semgrep" }

// config picks the ruleset: the Config field when set, then env
// BUGHOUND_SEMGREP_CONFIG, then the default `p/default`. `auto` is deliberately
// not the default because it is incompatible with --metrics=off. The Docker
// image pre-bakes the `p/default` ruleset into a local file and points
// BUGHOUND_SEMGREP_CONFIG at it (+SEMGREP_ENABLE_VERSION_CHECK=0) → semgrep
// SAST runs OFFLINE, without touching the registry, while runtime egress is
// locked.
func (r *Runner) config() string {
	if strings.TrimSpace(r.Config) != "" {
		return r.Config
	}
	if c := strings.TrimSpace(os.Getenv("BUGHOUND_SEMGREP_CONFIG")); c != "" {
		return c
	}
	return "p/default"
}

// args builds the semgrep arguments (kept separate so they can be tested
// without executing anything). --no-rewrite-rule-ids: keep rule ids as they
// are. Without this flag, when the config is a file PATH (the pre-baked local
// ruleset; see config()), semgrep prefixes each id with a namespace taken from
// the file path (e.g. "opt.semgrep."). That pollutes Type/SourceTemplate and
// gives the same finding a different dedup_key than in `p/default` registry
// mode. With a registry shorthand the flag is a no-op.
func (r *Runner) args(dir string) []string {
	return []string{"--json", "--quiet", "--metrics=off", "--no-rewrite-rule-ids", "--config", r.config(), dir}
}

// Analyze runs semgrep on dir and returns normalized findings.
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
			// semgrep: exit 1 = findings present (normal); >1 = a real error.
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

// Parse normalizes semgrep's JSON output into the Uniform Finding Schema.
// program/run_id/target are filled in by Run. It does not touch the network.
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
			Confidence:     mapConfidenceHML(res.Extra.Metadata.Confidence),
			Status:         finding.StatusNew,
			SourceEngine:   "semgrep",
			SourceTemplate: res.CheckID,
			CWE:            normalizeCWE(res.Extra.Metadata.CWE),
			References:     res.Extra.Metadata.References,
			Location:       finding.Location{URL: loc},
		}
		if m := strings.TrimSpace(res.Extra.Lines); m != "" && !isPlaceholderLines(m) {
			f.Evidence = &finding.Evidence{Matched: m}
		}
		fs = append(fs, f)
	}
	return fs, nil
}

// isPlaceholderLines reports whether semgrep's `lines` field is only a registry
// placeholder ("requires login" when semgrep is not authenticated) rather than
// a real code snippet. Such a placeholder is useless as evidence and must not
// clutter the report; the file:line location stays accurate through Location.
func isPlaceholderLines(s string) bool {
	return strings.EqualFold(strings.TrimSpace(s), "requires login")
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

// mapConfidenceHML maps a HIGH/MEDIUM/LOW-style confidence (used by semgrep and
// bandit) to the enum; the default is MEDIUM.
func mapConfidenceHML(s string) finding.Confidence {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "HIGH":
		return finding.ConfidenceHigh
	case "LOW":
		return finding.ConfidenceLow
	default:
		return finding.ConfidenceMedium
	}
}

// normalizeCWE takes the "CWE-###" code from entries such as "CWE-798: Use of ...".
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

// sampleSemgrepJSON is recorded semgrep output for testing Parse (no binary).
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
