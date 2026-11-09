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

// BanditRunner adalah adapter SAST untuk Bandit (analisis statis Python).
// Menjalankan `bandit -r -f json -q <dir>` lalu menormalkan JSON native-nya
// (lebih stabil & kaya metadata — CWE, confidence — dibanding output SARIF
// bandit yang butuh formatter tambahan). OPT-IN: butuh biner `bandit`.
//
// Tak menyentuh jaringan; dikurung ke dir in-scope (dijamin Resolve). Hanya
// menganalisis berkas Python; dir tanpa .py menghasilkan 0 temuan (bukan error).
type BanditRunner struct {
	Bin string // default "bandit"
}

// Name memenuhi Engine.
func (r *BanditRunner) Name() string { return "bandit" }

// args menyusun argumen bandit (dipisah agar bisa diuji tanpa mengeksekusi).
// -r rekursif, -f json keluaran mesin, -q diam (tanpa progress ke stderr).
func (r *BanditRunner) args(dir string) []string {
	return []string{"-r", "-f", "json", "-q", dir}
}

// Analyze menjalankan bandit pada dir dan mengembalikan temuan ternormalkan.
func (r *BanditRunner) Analyze(ctx context.Context, dir, _, _ string) ([]*finding.Finding, error) {
	bin := r.Bin
	if bin == "" {
		bin = "bandit"
	}
	cmd := exec.CommandContext(ctx, bin, r.args(dir)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// bandit keluar kode 1 saat menemukan isu (normal), 0 bila bersih. Kode exit
	// tak dijadikan sinyal error: bandit -f json selalu menulis laporan penuh ke
	// stdout, jadi keberhasilan diukur dari apakah JSON-nya bisa diurai.
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

// parseBandit menormalkan output JSON bandit ke Skema Temuan Seragam. dir dipakai
// untuk membuat path file relatif (lebih rapi di report). program/run_id/target
// diisi oleh Run. Tak menyentuh jaringan.
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

// mapBanditSeverity memetakan severity bandit (LOW/MEDIUM/HIGH) ke enum.
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

// relPath membuat file relatif terhadap dir bila memungkinkan; selain itu apa
// adanya. Menjaga report tetap ringkas (path repo-relatif, bukan absolut panjang).
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
