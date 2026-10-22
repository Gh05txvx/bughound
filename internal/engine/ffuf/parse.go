// Package ffuf menormalkan output ffuf (content discovery / fuzzing) ke Skema
// Temuan Seragam (BH-SPEC-FINDING), membuktikan nilai inti bughound: menambah
// engine = menambah satu adapter, tanpa menyentuh triase/report/store.
//
// Menyediakan engine mock untuk M1 (tanpa jaringan).
package ffuf

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"bughound/internal/finding"
)

// ffuf -of json menghasilkan satu objek JSON dengan array "results".
type ffufOutput struct {
	Results []ffufResult `json:"results"`
}

type ffufResult struct {
	Input       map[string]string `json:"input"`
	Status      int               `json:"status"`
	Length      int64             `json:"length"`
	Words       int64             `json:"words"`
	Lines       int64             `json:"lines"`
	ContentType string            `json:"content-type"`
	URL         string            `json:"url"`
	Host        string            `json:"host"`
}

// Parse membaca output ffuf (JSON) dan mengembalikan temuan ternormalkan.
func Parse(r io.Reader, program, runID string) ([]*finding.Finding, error) {
	var out ffufOutput
	if err := json.NewDecoder(r).Decode(&out); err != nil {
		return nil, fmt.Errorf("ffuf: output bukan JSON valid: %w", err)
	}
	var findings []*finding.Finding
	for i, res := range out.Results {
		f, err := mapResult(res, program, runID)
		if err != nil {
			return nil, fmt.Errorf("ffuf: hasil %d: %w", i, err)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func mapResult(res ffufResult, program, runID string) (*finding.Finding, error) {
	if strings.TrimSpace(res.URL) == "" {
		return nil, fmt.Errorf("hasil ffuf tanpa url")
	}
	fuzz := res.Input["FUZZ"]
	title := "Endpoint ditemukan"
	if fuzz != "" {
		title = "Endpoint ditemukan: " + fuzz
	}
	raw, _ := json.Marshal(res)

	return &finding.Finding{
		Program:      program,
		RunID:        runID,
		Target:       firstNonEmpty(res.Host, res.URL),
		Type:         "exposed-path",
		Title:        title,
		Severity:     mapSeverity(res.Status),
		Confidence:   finding.ConfidenceHigh, // ffuf melaporkan match pasti
		Tags:         []string{"content-discovery"},
		Location:     finding.Location{URL: res.URL},
		SourceEngine: "ffuf",
		Status:       finding.StatusNew,
		Evidence: &finding.Evidence{
			Payload: fuzz,
			Matched: fmt.Sprintf("HTTP %d · %d bytes · %d kata · %s", res.Status, res.Length, res.Words, res.ContentType),
		},
		Raw: raw,
	}, nil
}

// mapSeverity: ffuf menemukan path, bukan kerentanan langsung. 200/204 (dapat
// diakses) diberi low; selain itu info. Severity sebenarnya ditentukan saat
// triase manual.
func mapSeverity(status int) finding.Severity {
	switch status {
	case 200, 204:
		return finding.SeverityLow
	default:
		return finding.SeverityInfo
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
