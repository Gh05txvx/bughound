package retire

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"bughound/internal/finding"
)

// Bentuk output `retire --outputformat json`: objek dengan array "data"; tiap
// entri satu berkas JS yang dipindai, berisi "results" (komponen terdeteksi) dan
// tiap komponen punya "vulnerabilities".
type retireOutput struct {
	Data []retireFile `json:"data"`
}

type retireFile struct {
	File    string         `json:"file"`
	Results []retireResult `json:"results"`
}

type retireResult struct {
	Component       string       `json:"component"`
	Version         string       `json:"version"`
	Vulnerabilities []retireVuln `json:"vulnerabilities"`
}

type retireVuln struct {
	Info        []string          `json:"info"` // URL referensi advisory
	Severity    string            `json:"severity"`
	Identifiers retireIdentifiers `json:"identifiers"`
}

type retireIdentifiers struct {
	Summary string   `json:"summary"`
	CVE     []string `json:"CVE"`
}

// Parse menormalkan output JSON retire.js ke Skema Temuan Seragam. fileToURL
// memetakan basename berkas JS sementara (mis. "000.js") ke URL asalnya, agar
// temuan menunjuk ke aset nyata yang disajikan target, bukan path sementara.
// Seperti adapter lain, Parse tak memanggil Finalize — store yang mengisi
// id/dedup_key/created_at/schema_version saat menyimpan.
func Parse(out []byte, fileToURL map[string]string, target, program, runID string) ([]*finding.Finding, error) {
	if len(strings.TrimSpace(string(out))) == 0 {
		return nil, nil
	}
	var ro retireOutput
	if err := json.Unmarshal(out, &ro); err != nil {
		return nil, fmt.Errorf("retire: output bukan JSON valid: %w", err)
	}
	var findings []*finding.Finding
	for _, fe := range ro.Data {
		loc := fileToURL[filepath.Base(fe.File)]
		if loc == "" {
			loc = target
		}
		for _, res := range fe.Results {
			for _, v := range res.Vulnerabilities {
				findings = append(findings, mapVuln(res, v, loc, target, program, runID))
			}
		}
	}
	return findings, nil
}

func mapVuln(res retireResult, v retireVuln, locURL, target, program, runID string) *finding.Finding {
	comp := strings.TrimSpace(res.Component)
	ver := strings.TrimSpace(res.Version)
	label := comp
	if ver != "" {
		label = comp + " " + ver
	}

	cves := nonEmpty(v.Identifiers.CVE)
	payload := comp + "@" + ver
	if len(cves) > 0 {
		payload += " · " + strings.Join(cves, ", ")
	}

	matched := strings.TrimSpace(v.Identifiers.Summary)
	if matched == "" {
		matched = "library dengan kerentanan diketahui"
	}

	cveSuffix := ""
	if len(cves) > 0 {
		cveSuffix = " (" + strings.Join(cves, ", ") + ")"
	}
	desc := fmt.Sprintf("retire.js mendeteksi %s dengan kerentanan diketahui%s, dimuat dari %s. "+
		"Verifikasi manual apakah jalur/fungsi yang rentan benar-benar terpakai sebelum melaporkan.",
		label, cveSuffix, locURL)

	raw, _ := json.Marshal(struct {
		Component string   `json:"component"`
		Version   string   `json:"version"`
		Severity  string   `json:"severity"`
		CVE       []string `json:"cve,omitempty"`
		Summary   string   `json:"summary,omitempty"`
	}{comp, ver, v.Severity, cves, strings.TrimSpace(v.Identifiers.Summary)})

	return &finding.Finding{
		Program:      program,
		RunID:        runID,
		Target:       target,
		Type:         "vulnerable-dependency",
		Title:        "Library JS rentan: " + label,
		Description:  desc,
		Severity:     mapSeverity(v.Severity),
		Confidence:   finding.ConfidenceMedium, // cocok-versi; verifikasi manual pemakaian nyata
		CWE:          nil,
		Tags:         []string{"dependency", "outdated", "sca"},
		Location:     finding.Location{URL: locURL},
		Evidence:     &finding.Evidence{Payload: payload, Matched: matched},
		References:   httpRefs(v.Info),
		SourceEngine: "retire",
		Status:       finding.StatusNew,
		Raw:          raw,
	}
}

// mapSeverity memetakan severity retire.js ke enum skema. retire.js hanya
// menandai library yang BENAR-BENAR punya advisory, jadi severity tak dikenal
// tetap bermakna: default ke medium (bukan diturunkan jadi info).
func mapSeverity(s string) finding.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return finding.SeverityCritical
	case "high":
		return finding.SeverityHigh
	case "medium", "moderate":
		return finding.SeverityMedium
	case "low":
		return finding.SeverityLow
	default:
		return finding.SeverityMedium
	}
}

// nonEmpty menyaring string kosong dari slice.
func nonEmpty(in []string) []string {
	var out []string
	for _, s := range in {
		if strings.TrimSpace(s) != "" {
			out = append(out, strings.TrimSpace(s))
		}
	}
	return out
}

// httpRefs menyaring entri info menjadi hanya URL http(s) untuk References.
func httpRefs(in []string) []string {
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
			out = append(out, s)
		}
	}
	return out
}
