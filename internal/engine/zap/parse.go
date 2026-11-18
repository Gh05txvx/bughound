// Package zap normalizes an OWASP ZAP (DAST) report to the Uniform Finding Schema
// (BH-SPEC-FINDING). It provides a Mock (no network) and a real Runner
// (zap.sh quickscan subprocess), proving the pattern "add an engine = add one
// adapter".
package zap

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"

	"bughound/internal/finding"
)

type zapReport struct {
	Site []zapSite `json:"site"`
}

type zapSite struct {
	Name   string     `json:"@name"`
	Alerts []zapAlert `json:"alerts"`
}

type zapAlert struct {
	PluginID   string        `json:"pluginid"`
	Alert      string        `json:"alert"`
	RiskCode   string        `json:"riskcode"`
	Confidence string        `json:"confidence"`
	Desc       string        `json:"desc"`
	Solution   string        `json:"solution"`
	Reference  string        `json:"reference"`
	CWEID      string        `json:"cweid"`
	Instances  []zapInstance `json:"instances"`
}

type zapInstance struct {
	URI      string `json:"uri"`
	Method   string `json:"method"`
	Param    string `json:"param"`
	Evidence string `json:"evidence"`
}

// Parse reads a ZAP JSON report and returns normalized findings: one
// finding per instance (per URI/param), or one per alert when there is no instance.
func Parse(r io.Reader, program, runID string) ([]*finding.Finding, error) {
	var rep zapReport
	if err := json.NewDecoder(r).Decode(&rep); err != nil {
		return nil, fmt.Errorf("zap: output is not valid JSON: %w", err)
	}
	var out []*finding.Finding
	for _, site := range rep.Site {
		for _, a := range site.Alerts {
			base := alertToFinding(site, a, program, runID)
			if len(a.Instances) == 0 {
				base.Location = finding.Location{URL: firstNonEmpty(site.Name, "unknown")}
				out = append(out, base)
				continue
			}
			for _, inst := range a.Instances {
				f := cloneFinding(base)
				f.Location = finding.Location{
					URL:       firstNonEmpty(inst.URI, site.Name),
					Method:    inst.Method,
					Parameter: inst.Param,
				}
				if ev := strings.TrimSpace(inst.Evidence); ev != "" {
					f.Evidence = &finding.Evidence{Matched: ev}
				}
				out = append(out, f)
			}
		}
	}
	return out, nil
}

func alertToFinding(site zapSite, a zapAlert, program, runID string) *finding.Finding {
	f := &finding.Finding{
		Program:        program,
		RunID:          runID,
		Target:         site.Name,
		Type:           slug(a.Alert),
		Title:          strings.TrimSpace(a.Alert),
		Description:    stripHTML(a.Desc),
		Severity:       mapRisk(a.RiskCode),
		Confidence:     mapConfidence(a.Confidence),
		Status:         finding.StatusNew,
		SourceEngine:   "zap",
		SourceTemplate: a.PluginID,
	}
	if cwe := normalizeCWE(a.CWEID); cwe != "" {
		f.CWE = []string{cwe}
	}
	if ref := strings.TrimSpace(a.Reference); ref != "" {
		f.References = []string{ref}
	}
	return f
}

func cloneFinding(f *finding.Finding) *finding.Finding {
	c := *f
	return &c
}

// mapRisk maps the ZAP riskcode (0 info .. 3 high) to severity.
func mapRisk(code string) finding.Severity {
	switch strings.TrimSpace(code) {
	case "3":
		return finding.SeverityHigh
	case "2":
		return finding.SeverityMedium
	case "1":
		return finding.SeverityLow
	default:
		return finding.SeverityInfo
	}
}

// mapConfidence maps ZAP confidence (0 FP .. 4 confirmed) to confidence.
func mapConfidence(code string) finding.Confidence {
	switch strings.TrimSpace(code) {
	case "4", "3":
		return finding.ConfidenceHigh
	case "2":
		return finding.ConfidenceMedium
	default:
		return finding.ConfidenceLow
	}
}

func normalizeCWE(id string) string {
	id = strings.TrimSpace(id)
	if id == "" || id == "-1" || id == "0" {
		return ""
	}
	if strings.HasPrefix(strings.ToUpper(id), "CWE-") {
		return strings.ToUpper(id)
	}
	return "CWE-" + id
}

var tagRE = regexp.MustCompile(`<[^>]*>`)
var wsRE = regexp.MustCompile(`\s+`)

func stripHTML(s string) string {
	s = tagRE.ReplaceAllString(s, " ")
	s = strings.ReplaceAll(s, "&lt;", "<")
	s = strings.ReplaceAll(s, "&gt;", ">")
	s = strings.ReplaceAll(s, "&amp;", "&")
	return strings.TrimSpace(wsRE.ReplaceAllString(s, " "))
}

func slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	prevHyphen := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevHyphen = false
		default:
			if !prevHyphen && b.Len() > 0 {
				b.WriteByte('-')
				prevHyphen = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
