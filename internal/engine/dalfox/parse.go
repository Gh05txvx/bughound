package dalfox

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"strings"

	"bughound/internal/finding"
)

// dalfoxPoC mirrors one PoC entry in dalfox's JSON output (model.PoC in
// dalfox v2). Only the fields we use are defined; the rest are ignored.
type dalfoxPoC struct {
	Type        string `json:"type"`         // V=verified, R=reflected, G=grep/bav
	InjectType  string `json:"inject_type"`  // mis. "inHTML-URL", "inJS-double"
	Method      string `json:"method"`       // GET/POST
	Data        string `json:"data"`         // PoC URL (payload embedded)
	Param       string `json:"param"`        // affected parameter
	Payload     string `json:"payload"`      // the payload sent
	Evidence    string `json:"evidence"`     // evidence snippet
	CWE         string `json:"cwe"`          // mis. "CWE-79"
	Severity    string `json:"severity"`     // High/Medium/Low/Info
	MessageStr  string `json:"message_str"`  // description (optional)
	RawRequest  string `json:"raw_request"`  // raw HTTP request (optional)
	RawResponse string `json:"raw_response"` // raw HTTP response (optional)
}

// dalfoxResult wraps the PoC list when dalfox writes a full Result object.
type dalfoxResult struct {
	PoCs []dalfoxPoC `json:"pocs"`
}

// Parse normalizes dalfox's JSON output to the Uniform Finding Schema (BH-SPEC-FINDING).
// Tolerant of the three forms dalfox may emit: a Result object
// (`{"pocs":[...]}`), a PoC array (`[...]`), or JSONL (one PoC object per line).
// program/run_id/target are filled here; the store fills id/dedup_key/schema/created.
func Parse(r io.Reader, target, program, runID string) ([]*finding.Finding, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var out []*finding.Finding
	for _, p := range extractPoCs(data) {
		if f := mapPoC(p, target, program, runID); f != nil {
			out = append(out, f)
		}
	}
	return out, nil
}

// extractPoCs parses the PoC list from dalfox output, tolerant of the
// form (Result object / array / JSONL). Invalid lines/entries are skipped.
func extractPoCs(data []byte) []dalfoxPoC {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil
	}
	switch data[0] {
	case '{':
		// Result object {"pocs":[...]}.
		var res dalfoxResult
		if json.Unmarshal(data, &res) == nil && res.PoCs != nil {
			return res.PoCs
		}
		// A single PoC object.
		var single dalfoxPoC
		if json.Unmarshal(data, &single) == nil && !single.empty() {
			return []dalfoxPoC{single}
		}
	case '[':
		// Array PoC.
		var arr []dalfoxPoC
		if json.Unmarshal(data, &arr) == nil {
			return arr
		}
	}
	// JSONL: one object per line (dalfox stream mode).
	var out []dalfoxPoC
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var p dalfoxPoC
		if json.Unmarshal(line, &p) == nil && !p.empty() {
			out = append(out, p)
		}
	}
	return out
}

func (p dalfoxPoC) empty() bool {
	return strings.TrimSpace(p.Data) == "" && strings.TrimSpace(p.Payload) == "" && strings.TrimSpace(p.Evidence) == ""
}

// mapPoC maps one dalfox PoC to a Finding. Returns nil when the PoC is empty.
func mapPoC(p dalfoxPoC, target, program, runID string) *finding.Finding {
	if p.empty() {
		return nil
	}
	typ := mapType(p.CWE, p.InjectType)
	locURL := strings.TrimSpace(p.Data)
	if locURL == "" {
		locURL = target
	}
	f := &finding.Finding{
		Program:        program,
		RunID:          runID,
		Target:         target,
		Type:           typ,
		Title:          buildTitle(typ, p.Type, p.Param),
		Description:    strings.TrimSpace(p.MessageStr),
		Severity:       mapSeverity(p.Severity),
		Confidence:     mapConfidence(p.Type),
		Status:         finding.StatusNew,
		SourceEngine:   "dalfox",
		SourceTemplate: strings.TrimSpace(p.InjectType),
		Location: finding.Location{
			URL:       locURL,
			Method:    strings.ToUpper(strings.TrimSpace(p.Method)),
			Parameter: strings.TrimSpace(p.Param),
		},
	}
	if cwe := strings.ToUpper(strings.TrimSpace(p.CWE)); cwe != "" {
		f.CWE = []string{cwe}
	}
	if e := buildEvidence(p); e != nil {
		f.Evidence = e
	}
	return f
}

// buildEvidence assembles Evidence from the PoC, redacting sensitive headers in the
// raw request/response (BH-SPEC-FINDING: the schema never stores a raw
// secret). Returns nil when there is no evidence material.
func buildEvidence(p dalfoxPoC) *finding.Evidence {
	e := &finding.Evidence{
		Request:         redactHTTP(p.RawRequest),
		ResponseExcerpt: redactHTTP(p.RawResponse),
		Payload:         strings.TrimSpace(p.Payload),
		Matched:         strings.TrimSpace(p.Evidence),
	}
	if e.Request == "" && e.ResponseExcerpt == "" && e.Payload == "" && e.Matched == "" {
		return nil
	}
	return e
}

// sensitiveHeaders are the headers whose values are redacted from evidence.
var sensitiveHeaders = []string{"authorization:", "proxy-authorization:", "cookie:", "set-cookie:", "x-api-key:", "x-auth-token:"}

// redactHTTP redacts the VALUE of sensitive headers (Authorization/Cookie/etc.) in
// raw HTTP text, keeping the header name so the structure stays readable.
func redactHTTP(s string) string {
	if strings.TrimSpace(s) == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	for i, ln := range lines {
		low := strings.ToLower(strings.TrimSpace(ln))
		for _, h := range sensitiveHeaders {
			if strings.HasPrefix(low, h) {
				if idx := strings.Index(ln, ":"); idx >= 0 {
					lines[i] = ln[:idx+1] + " [REDACTED]"
				}
				break
			}
		}
	}
	return strings.Join(lines, "\n")
}

// mapType normalizes the finding type from the CWE (dalfox fills a specific CWE for
// a non-XSS finding from BAV), then falls back to "xss" (dalfox focuses on XSS).
func mapType(cwe, injectType string) string {
	switch strings.ToUpper(strings.TrimSpace(cwe)) {
	case "CWE-79":
		return "xss"
	case "CWE-601":
		return "open-redirect"
	case "CWE-89":
		return "sqli"
	case "CWE-1336", "CWE-94":
		return "ssti"
	case "CWE-113":
		return "crlf-injection"
	}
	return "xss"
}

// mapSeverity maps dalfox severity (High/Medium/Low/Info) to the schema.
func mapSeverity(s string) finding.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return finding.SeverityCritical
	case "HIGH":
		return finding.SeverityHigh
	case "MEDIUM":
		return finding.SeverityMedium
	case "LOW":
		return finding.SeverityLow
	case "INFO":
		return finding.SeverityInfo
	}
	return finding.SeverityMedium
}

// mapConfidence maps the dalfox PoC type to confidence: V(erified)=high (passed
// headless verification), R(eflected)=medium, G(rep/BAV)=low.
func mapConfidence(pocType string) finding.Confidence {
	switch strings.ToUpper(strings.TrimSpace(pocType)) {
	case "V":
		return finding.ConfidenceHigh
	case "R":
		return finding.ConfidenceMedium
	case "G":
		return finding.ConfidenceLow
	}
	return finding.ConfidenceMedium
}

// buildTitle builds a short title from type + verification level + parameter.
func buildTitle(typ, pocType, param string) string {
	label := map[string]string{
		"xss":            "XSS",
		"open-redirect":  "Open Redirect",
		"sqli":           "SQL Injection",
		"ssti":           "SSTI",
		"crlf-injection": "CRLF Injection",
	}[typ]
	if label == "" {
		label = strings.ToUpper(typ)
	}
	if v := map[string]string{"V": "verified", "R": "reflected", "G": "heuristic"}[strings.ToUpper(strings.TrimSpace(pocType))]; v != "" {
		label += " (" + v + ")"
	}
	if p := strings.TrimSpace(param); p != "" {
		label += " on parameter `" + p + "`"
	}
	return truncate(label, 160)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
