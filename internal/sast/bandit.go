package sast

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"

	"bughound/internal/finding"
)

// BanditRunner is the SAST adapter for Bandit (static analysis for Python).
// It runs `bandit -r -f json -q <dir>` and normalizes its native JSON (more
// stable and richer in metadata, such as CWE and confidence, than bandit's
// SARIF output, which needs an extra formatter). OPT-IN: needs the `bandit`
// binary.
//
// It does not touch the network and is confined to the in-scope dir
// (guaranteed by Resolve). It only analyzes Python files; a dir without .py
// files yields 0 findings (not an error).
type BanditRunner struct {
	Bin string // default "bandit"
}

// Name implements Engine.
func (r *BanditRunner) Name() string { return "bandit" }

// args builds the bandit arguments (kept separate so they can be tested
// without executing anything). -r recursive, -f json machine output, -q quiet
// (no progress on stderr).
func (r *BanditRunner) args(dir string) []string {
	return []string{"-r", "-f", "json", "-q", dir}
}

// Analyze runs bandit on dir and returns normalized findings.
func (r *BanditRunner) Analyze(ctx context.Context, dir, _, _ string) ([]*finding.Finding, error) {
	bin := r.Bin
	if bin == "" {
		bin = "bandit"
	}
	cmd := exec.CommandContext(ctx, bin, r.args(dir)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// bandit exits with code 1 when it finds issues (normal) and 0 when clean. The
	// exit code is not treated as an error signal: bandit -f json always writes
	// the full report to stdout, so success is measured by whether its JSON parses.
	runErr := cmd.Run()
	fs, perr := parseBandit(bytes.NewReader(stdout.Bytes()), dir)
	if perr != nil {
		if runErr != nil {
			return nil, fmt.Errorf("bandit: %v: %s", runErr, strings.TrimSpace(stderr.String()))
		}
		return nil, fmt.Errorf("bandit: %w", perr)
	}
	return fs, nil
}

type banditOutput struct {
	Results []banditResult `json:"results"`
}

type banditResult struct {
	Filename        string `json:"filename"`
	LineNumber      int    `json:"line_number"`
	TestID          string `json:"test_id"`
	TestName        string `json:"test_name"`
	IssueText       string `json:"issue_text"`
	IssueSeverity   string `json:"issue_severity"`
	IssueConfidence string `json:"issue_confidence"`
	IssueCWE        struct {
		ID   int    `json:"id"`
		Link string `json:"link"`
	} `json:"issue_cwe"`
	Code     string `json:"code"`
	MoreInfo string `json:"more_info"`
}

// parseBandit normalizes bandit's JSON output into the Uniform Finding Schema.
// dir is used to make file paths relative (tidier in reports).
// program/run_id/target are filled in by Run. It does not touch the network.
func parseBandit(r io.Reader, dir string) ([]*finding.Finding, error) {
	var out banditOutput
	if err := json.NewDecoder(r).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode json: %w", err)
	}
	var fs []*finding.Finding
	for _, res := range out.Results {
		path := relPath(dir, res.Filename)
		loc := path
		if res.LineNumber > 0 {
			loc = fmt.Sprintf("%s:%d", path, res.LineNumber)
		}
		title := strings.TrimSpace(res.IssueText)
		if title == "" {
			title = strings.TrimSpace(res.TestName)
		}
		if title == "" {
			title = res.TestID
		}
		var refs []string
		if u := strings.TrimSpace(res.MoreInfo); u != "" {
			refs = append(refs, u)
		}
		if u := strings.TrimSpace(res.IssueCWE.Link); u != "" {
			refs = append(refs, u)
		}
		var cwe []string
		if res.IssueCWE.ID > 0 {
			cwe = []string{fmt.Sprintf("CWE-%d", res.IssueCWE.ID)}
		}
		f := &finding.Finding{
			Type:           res.TestID,
			Title:          truncate(title, 160),
			Description:    strings.TrimSpace(res.IssueText),
			Severity:       mapBanditSeverity(res.IssueSeverity),
			Confidence:     mapConfidenceHML(res.IssueConfidence),
			Status:         finding.StatusNew,
			SourceEngine:   "bandit",
			SourceTemplate: res.TestID,
			CWE:            cwe,
			Tags:           []string{"sast", "bandit", "python"},
			References:     refs,
			Location:       finding.Location{URL: loc},
		}
		if code := strings.TrimSpace(res.Code); code != "" {
			f.Evidence = &finding.Evidence{Matched: truncate(code, 2000)}
		}
		fs = append(fs, f)
	}
	return fs, nil
}

// mapBanditSeverity maps bandit's severity (LOW/MEDIUM/HIGH) to the enum.
func mapBanditSeverity(s string) finding.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "HIGH":
		return finding.SeverityHigh
	case "MEDIUM":
		return finding.SeverityMedium
	case "LOW":
		return finding.SeverityLow
	default:
		return finding.SeverityInfo
	}
}

// relPath makes file relative to dir when possible, otherwise returns it as is.
// It keeps reports compact (repo-relative paths, not long absolute ones).
func relPath(dir, file string) string {
	if dir == "" || file == "" {
		return file
	}
	if rel, err := filepath.Rel(dir, file); err == nil && !strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(file)
}

func init() { Register("bandit", func() Engine { return &BanditRunner{} }) }
