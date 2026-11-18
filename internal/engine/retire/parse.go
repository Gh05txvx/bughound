package retire

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"bughound/internal/finding"
)

// The output form of `retire --outputformat json`: an object with a "data" array; each
// entry is one scanned JS file, holding "results" (detected components) and
// each component has "vulnerabilities".
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
	Info        []string          `json:"info"` // advisory reference URL
	Severity    string            `json:"severity"`
	Identifiers retireIdentifiers `json:"identifiers"`
}

type retireIdentifiers struct {
	Summary string   `json:"summary"`
	CVE     []string `json:"CVE"`
}

// Parse normalizes retire.js JSON output to the Uniform Finding Schema. fileToURL
// maps a temp JS file's basename (e.g. "000.js") to its origin URL, so a
// finding points to the real asset the target serves, not a temp path.
// Like the other adapters, Parse does not call Finalize — the store fills
// id/dedup_key/created_at/schema_version on save.
func Parse(out []byte, fileToURL map[string]string, target, program, runID string) ([]*finding.Finding, error) {
	if len(strings.TrimSpace(string(out))) == 0 {
		return nil, nil
	}
	var ro retireOutput
	if err := json.Unmarshal(out, &ro); err != nil {
		return nil, fmt.Errorf("retire: output is not valid JSON: %w", err)
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
		matched = "a library with a known vulnerability"
	}

	cveSuffix := ""
	if len(cves) > 0 {
		cveSuffix = " (" + strings.Join(cves, ", ") + ")"
	}
	desc := fmt.Sprintf("retire.js detected %s with a known vulnerability%s, loaded from %s. "+
		"Manually verify whether the vulnerable path/function is actually used before reporting.",
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
		Title:        "Vulnerable JS library: " + label,
		Description:  desc,
		Severity:     mapSeverity(v.Severity),
		Confidence:   finding.ConfidenceMedium, // version match; manually verify real usage
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

// mapSeverity maps retire.js severity to the schema enum. retire.js only
// flags a library that REALLY has an advisory, so an unknown severity
// still means something: default to medium (not downgraded to info).
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

// nonEmpty filters empty strings out of the slice.
func nonEmpty(in []string) []string {
	var out []string
	for _, s := range in {
		if strings.TrimSpace(s) != "" {
			out = append(out, strings.TrimSpace(s))
		}
	}
	return out
}

// httpRefs filters info entries down to only http(s) URLs for References.
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
