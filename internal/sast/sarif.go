package sast

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"bughound/internal/finding"
)

// NormalizeSARIF normalizes a SARIF 2.1.0 report into the Uniform Finding
// Schema. It is shared by the SAST adapters whose tool can emit SARIF
// (gitleaks, findsecbugs and, through future adapters, codeql, etc.). engine =
// the calling adapter's name, used for SourceEngine so it matches the registry.
//
// redact (optional) masks the code snippet before it is stored as evidence. It
// is REQUIRED for secret-scanning tools (Principle #5: secrets never leak into
// the store/reports). When redact returns an empty string, the evidence is not
// filled in. redact nil = the snippet is used as is (safe for ordinary code
// SAST).
//
// program/run_id/target are filled in by Run. It does not touch the network.
func NormalizeSARIF(data []byte, engine string, redact func(string) string) ([]*finding.Finding, error) {
	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		return nil, fmt.Errorf("%s: decode sarif: %w", engine, err)
	}
	var fs []*finding.Finding
	for _, run := range log.Runs {
		// Index rules by id to resolve metadata (default severity, CWE, help).
		byID := make(map[string]*sarifRule, len(run.Tool.Driver.Rules))
		rules := run.Tool.Driver.Rules
		for i := range rules {
			byID[rules[i].ID] = &rules[i]
		}
		for _, res := range run.Results {
			var rule *sarifRule
			if res.RuleIndex != nil && *res.RuleIndex >= 0 && *res.RuleIndex < len(rules) {
				rule = &rules[*res.RuleIndex]
			} else if r, ok := byID[res.RuleID]; ok {
				rule = r
			}

			ruleID := res.RuleID
			if ruleID == "" && rule != nil {
				ruleID = rule.ID
			}

			msg := strings.TrimSpace(res.Message.Text)
			title := msg
			if rule != nil {
				if t := strings.TrimSpace(rule.ShortDescription.Text); t != "" {
					title = t
				} else if rule.Name != "" {
					title = rule.Name
				}
			}
			if title == "" {
				title = ruleID
			}
			desc := msg
			if desc == "" && rule != nil {
				desc = strings.TrimSpace(rule.FullDescription.Text)
			}

			uri, line, snippet := firstLocation(res.Locations)
			loc := uri
			if line > 0 {
				loc = fmt.Sprintf("%s:%d", uri, line)
			}

			f := &finding.Finding{
				Type:           ruleID,
				Title:          truncate(title, 160),
				Description:    desc,
				Severity:       sarifSeverity(res, rule),
				Confidence:     finding.ConfidenceMedium,
				Status:         finding.StatusNew,
				SourceEngine:   engine,
				SourceTemplate: ruleID,
				CWE:            sarifCWE(res, rule),
				Tags:           sarifTags(engine, rule),
				References:     sarifRefs(rule),
				Location:       finding.Location{URL: loc},
			}
			if s := strings.TrimSpace(snippet); s != "" {
				if redact != nil {
					s = strings.TrimSpace(redact(s))
				}
				if s != "" {
					f.Evidence = &finding.Evidence{Matched: s}
				}
			}
			fs = append(fs, f)
		}
	}
	return fs, nil
}

// firstLocation takes the uri/line/snippet from the first physical location.
func firstLocation(locs []sarifLocation) (uri string, line int, snippet string) {
	for _, l := range locs {
		p := l.PhysicalLocation
		if p.ArtifactLocation.URI == "" {
			continue
		}
		return p.ArtifactLocation.URI, p.Region.StartLine, p.Region.Snippet.Text
	}
	return "", 0, ""
}

// sarifSeverity maps a SARIF severity. Priority: numeric security-severity
// (GitHub convention, the most precise) → the result level → the rule's default
// level. "error" counts as high for SAST (a finding, not just style).
func sarifSeverity(res sarifResult, rule *sarifRule) finding.Severity {
	ss := strings.TrimSpace(res.Properties.SecuritySeverity)
	if ss == "" && rule != nil {
		ss = strings.TrimSpace(rule.Properties.SecuritySeverity)
	}
	if ss != "" {
		if v, err := strconv.ParseFloat(ss, 64); err == nil {
			switch {
			case v >= 9.0:
				return finding.SeverityCritical
			case v >= 7.0:
				return finding.SeverityHigh
			case v >= 4.0:
				return finding.SeverityMedium
			case v > 0:
				return finding.SeverityLow
			}
		}
	}
	level := strings.ToLower(strings.TrimSpace(res.Level))
	if level == "" && rule != nil {
		level = strings.ToLower(strings.TrimSpace(rule.DefaultConfiguration.Level))
	}
	switch level {
	case "error":
		return finding.SeverityHigh
	case "warning":
		return finding.SeverityMedium
	case "note", "none":
		return finding.SeverityInfo
	default:
		return finding.SeverityLow
	}
}

// sarifCWE collects CWEs from properties.cwe (a string or an array) and from
// CodeQL-style tags "external/cwe/cwe-079" → "CWE-79".
func sarifCWE(res sarifResult, rule *sarifRule) []string {
	seen := map[string]bool{}
	var out []string
	add := func(code string) {
		code = normalizeCWECode(code)
		if code != "" && !seen[code] {
			seen[code] = true
			out = append(out, code)
		}
	}
	for _, c := range res.Properties.cweList() {
		add(c)
	}
	if rule != nil {
		for _, c := range rule.Properties.cweList() {
			add(c)
		}
		for _, t := range rule.Properties.Tags {
			if code, ok := cweFromTag(t); ok {
				add(code)
			}
		}
	}
	for _, t := range res.Properties.Tags {
		if code, ok := cweFromTag(t); ok {
			add(code)
		}
	}
	return out
}

// cweFromTag extracts a CWE from the tag "external/cwe/cwe-079" (CodeQL format).
func cweFromTag(tag string) (string, bool) {
	t := strings.ToLower(strings.TrimSpace(tag))
	i := strings.LastIndex(t, "cwe-")
	if i < 0 {
		return "", false
	}
	num := t[i+len("cwe-"):]
	if num == "" {
		return "", false
	}
	for _, r := range num {
		if r < '0' || r > '9' {
			return "", false
		}
	}
	return "CWE-" + strings.TrimLeft(num, "0"), true
}

// normalizeCWECode tidies one CWE entry into the "CWE-###" form.
func normalizeCWECode(c string) string {
	c = strings.TrimSpace(c)
	if c == "" {
		return ""
	}
	if i := strings.IndexByte(c, ':'); i > 0 { // "CWE-798: ..." → "CWE-798"
		c = strings.TrimSpace(c[:i])
	}
	low := strings.ToLower(c)
	if strings.HasPrefix(low, "cwe-") {
		return "CWE-" + strings.TrimLeft(c[4:], "0")
	}
	// bare number
	allDigit := true
	for _, r := range c {
		if r < '0' || r > '9' {
			allDigit = false
			break
		}
	}
	if allDigit {
		return "CWE-" + strings.TrimLeft(c, "0")
	}
	return c
}

// sarifTags joins the rule tags + the "sast" marker and the engine name.
func sarifTags(engine string, rule *sarifRule) []string {
	seen := map[string]bool{"sast": true, engine: true}
	out := []string{"sast", engine}
	if rule != nil {
		for _, t := range rule.Properties.Tags {
			t = strings.TrimSpace(t)
			// Drop CodeQL's technical tags (external/cwe/..., precision/...) from the
			// displayed list; the CWE is already lifted into the CWE field.
			if t == "" || strings.Contains(t, "/") {
				continue
			}
			if !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
	}
	return out
}

func sarifRefs(rule *sarifRule) []string {
	if rule == nil {
		return nil
	}
	if u := strings.TrimSpace(rule.HelpURI); u != "" {
		return []string{u}
	}
	return nil
}

// --- SARIF 2.1.0 structures (the subset we use) ---

type sarifLog struct {
	Runs []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool struct {
		Driver struct {
			Name  string      `json:"name"`
			Rules []sarifRule `json:"rules"`
		} `json:"driver"`
	} `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifRule struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	ShortDescription struct {
		Text string `json:"text"`
	} `json:"shortDescription"`
	FullDescription struct {
		Text string `json:"text"`
	} `json:"fullDescription"`
	HelpURI              string `json:"helpUri"`
	DefaultConfiguration struct {
		Level string `json:"level"`
	} `json:"defaultConfiguration"`
	Properties sarifProps `json:"properties"`
}

type sarifResult struct {
	RuleID    string `json:"ruleId"`
	RuleIndex *int   `json:"ruleIndex"`
	Level     string `json:"level"`
	Message   struct {
		Text string `json:"text"`
	} `json:"message"`
	Locations  []sarifLocation `json:"locations"`
	Properties sarifProps      `json:"properties"`
}

type sarifLocation struct {
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Region struct {
			StartLine int `json:"startLine"`
			Snippet   struct {
				Text string `json:"text"`
			} `json:"snippet"`
		} `json:"region"`
	} `json:"physicalLocation"`
}

// sarifProps holds the properties that can carry severity/CWE. cwe can be a
// single string or an array of strings, so it is kept raw and parsed loosely.
type sarifProps struct {
	Tags             []string        `json:"tags"`
	SecuritySeverity string          `json:"security-severity"`
	CWE              json.RawMessage `json:"cwe"`
}

// cweList parses properties.cwe, which can be a string or []string.
func (p sarifProps) cweList() []string {
	if len(p.CWE) == 0 {
		return nil
	}
	var arr []string
	if err := json.Unmarshal(p.CWE, &arr); err == nil {
		return arr
	}
	var one string
	if err := json.Unmarshal(p.CWE, &one); err == nil && one != "" {
		return []string{one}
	}
	return nil
}
