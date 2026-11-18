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

// GitleaksRunner is the SAST adapter for Gitleaks (detection of committed
// secrets: API keys, tokens, credentials). It runs `gitleaks detect` with SARIF
// output and normalizes it through the shared NormalizeSARIF.
//
// SECURITY (Principle #5: secrets never leak): redaction in layers. (1) gitleaks
// runs with `--redact`, so secret values are already masked at the source;
// (2) NormalizeSARIF gets redactSecret as a safety net that masks long tokens
// if anything slips through. The stored snippet shows the context (e.g. the
// variable name) without the secret value.
//
// OPT-IN: needs the `gitleaks` binary. It does not touch the network and is
// confined to the in-scope dir.
type GitleaksRunner struct {
	Bin string // default "gitleaks"
}

// Name implements Engine.
func (r *GitleaksRunner) Name() string { return "gitleaks" }

// args builds the gitleaks arguments. The report is written to a file (SARIF),
// not stdout. --no-git: scan the files as they are (the target need not be a
// git repo). --redact: mask secret values at the source. --exit-code 0: a
// finding is not an error condition (we measure success by a report that
// parses). --no-banner: no ASCII art.
func (r *GitleaksRunner) args(dir, report string) []string {
	return []string{
		"detect", "--source", dir, "--no-git",
		"--report-format", "sarif", "--report-path", report,
		"--redact", "--exit-code", "0", "--no-banner",
	}
}

// Analyze runs gitleaks on dir and returns normalized findings.
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
		// No readable report → if the process failed, that is a real error.
		if runErr != nil {
			return nil, fmt.Errorf("gitleaks: %v: %s", runErr, strings.TrimSpace(stderr.String()))
		}
		// The process succeeded but the report is empty = no findings (some gitleaks
		// versions may not write the file when there are zero leaks).
		return nil, nil
	}
	return parseGitleaks(data)
}

// parseGitleaks normalizes gitleaks SARIF and fills in secret-specific
// metadata: CWE-798 (hardcoded credentials) by default when empty, and the
// "secret" tag.
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

// redactSecret is a safety net: it masks long secret-like tokens (runs of >= 20
// base64/hex/url-safe chars) into a prefix + marker, keeping the context useful
// without leaking the value. It is applied on top of gitleaks' `--redact` as a
// second layer.
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

// ensureTag adds tag when it is not there yet.
func ensureTag(tags []string, tag string) []string {
	if slices.Contains(tags, tag) {
		return tags
	}
	return append(tags, tag)
}

func init() { Register("gitleaks", func() Engine { return &GitleaksRunner{} }) }
