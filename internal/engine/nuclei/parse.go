// Package nuclei normalizes nuclei output (JSONL) into the Unified Finding Schema
// (BH-SPEC-FINDING) and provides a mock engine for M0/E2E.
//
// This adapter never stores a raw secret: authentication header values in the
// request/response are redacted before they enter evidence OR raw.
package nuclei

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"bughound/internal/finding"
)

// stringList accepts a JSON value that is either a string array OR a single
// string (comma-separated), because different nuclei versions write
// tags/reference/cwe in one form or the other.
type stringList []string

func (s *stringList) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	if b[0] == '[' {
		var arr []string
		if err := json.Unmarshal(b, &arr); err != nil {
			return err
		}
		*s = arr
		return nil
	}
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	var out stringList
	for _, p := range strings.Split(str, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	*s = out
	return nil
}

type nucleiEvent struct {
	TemplateID       string     `json:"template-id"`
	Type             string     `json:"type"`
	Host             string     `json:"host"`
	MatchedAt        string     `json:"matched-at"`
	Request          string     `json:"request"`
	Response         string     `json:"response"`
	IP               string     `json:"ip"`
	Timestamp        string     `json:"timestamp"`
	MatcherStatus    bool       `json:"matcher-status"`
	MatcherName      string     `json:"matcher-name"`
	ExtractedResults stringList `json:"extracted-results"`
	Info             nucleiInfo `json:"info"`
}

type nucleiInfo struct {
	Name           string      `json:"name"`
	Description    string      `json:"description"`
	Severity       string      `json:"severity"`
	Tags           stringList  `json:"tags"`
	Reference      stringList  `json:"reference"`
	Classification nucleiClass `json:"classification"`
}

type nucleiClass struct {
	CWEID       stringList `json:"cwe-id"`
	CVEID       stringList `json:"cve-id"`
	CVSSMetrics string     `json:"cvss-metrics"`
	CVSSScore   float64    `json:"cvss-score"`
}

// Parse reads nuclei output in JSONL format and returns normalized findings.
// Blank lines and non-JSON lines (banners) are skipped; a broken JSON line
// produces an error.
func Parse(r io.Reader, program, runID string) ([]*finding.Finding, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024) // request/response can be large

	var out []*finding.Finding
	lineNo := 0
	for sc.Scan() {
		lineNo++
		b := bytes.TrimSpace(sc.Bytes())
		if len(b) == 0 || b[0] != '{' {
			continue
		}
		raw := make([]byte, len(b)) // the Scanner reuses its buffer
		copy(raw, b)

		var ev nucleiEvent
		if err := json.Unmarshal(raw, &ev); err != nil {
			return nil, fmt.Errorf("nuclei: line %d is not valid JSON: %w", lineNo, err)
		}
		f, err := mapEvent(&ev, raw, program, runID)
		if err != nil {
			return nil, fmt.Errorf("nuclei: line %d: %w", lineNo, err)
		}
		out = append(out, f)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("nuclei: failed to read output: %w", err)
	}
	return out, nil
}

func mapEvent(ev *nucleiEvent, raw []byte, program, runID string) (*finding.Finding, error) {
	locURL := firstNonEmpty(ev.MatchedAt, ev.Host)
	if locURL == "" {
		return nil, errors.New("event without matched-at/host")
	}

	// Redact request/response ONCE; used for both evidence and raw.
	sReq := sanitizeHTTP(ev.Request)
	sResp := sanitizeHTTP(ev.Response)

	typ := strings.ToLower(strings.TrimSpace(ev.TemplateID))
	if typ == "" {
		typ = "unknown"
	}

	f := &finding.Finding{
		Program:        program,
		RunID:          runID,
		Target:         firstNonEmpty(ev.Host, locURL),
		Type:           typ,
		Title:          firstNonEmpty(ev.Info.Name, ev.TemplateID, "nuclei finding"),
		Description:    ev.Info.Description,
		Severity:       mapSeverity(ev.Info.Severity),
		Confidence:     mapConfidence(ev),
		CWE:            cleanList(ev.Info.Classification.CWEID),
		Tags:           cleanList(ev.Info.Tags),
		Location:       finding.Location{URL: locURL, Method: methodFromRequest(sReq)},
		SourceEngine:   "nuclei",
		SourceTemplate: ev.TemplateID,
		References:     cleanList(ev.Info.Reference),
		Raw:            sanitizeRaw(raw, sReq, sResp),
		Status:         finding.StatusNew,
	}
	if c := mapCVSS(ev.Info.Classification); c != nil {
		f.CVSS = c
	}
	if e := mapEvidence(sReq, sResp, ev); e != nil {
		f.Evidence = e
	}
	if t, err := time.Parse(time.RFC3339, ev.Timestamp); err == nil {
		f.CreatedAt = finding.NewTime(t)
	}
	return f, nil
}

// sanitizeRaw keeps all of nuclei's raw fields but replaces request/response with
// the redacted version, so raw does not carry a secret either.
func sanitizeRaw(raw []byte, sReq, sResp string) json.RawMessage {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	if _, ok := m["request"]; ok {
		if b, err := json.Marshal(sReq); err == nil {
			m["request"] = b
		}
	}
	if _, ok := m["response"]; ok {
		if b, err := json.Marshal(sResp); err == nil {
			m["response"] = b
		}
	}
	out, err := json.Marshal(m)
	if err != nil {
		return nil
	}
	return out
}

func mapEvidence(sReq, sResp string, ev *nucleiEvent) *finding.Evidence {
	matched := ev.MatcherName
	if matched == "" && len(ev.ExtractedResults) > 0 {
		matched = strings.Join(ev.ExtractedResults, ", ")
	}
	resp := truncate(sResp, 4096)
	if sReq == "" && resp == "" && matched == "" {
		return nil
	}
	return &finding.Evidence{
		Request:         sReq,
		ResponseExcerpt: resp,
		Matched:         matched,
	}
}

func mapSeverity(s string) finding.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return finding.SeverityCritical
	case "high":
		return finding.SeverityHigh
	case "medium":
		return finding.SeverityMedium
	case "low":
		return finding.SeverityLow
	default: // info, unknown, empty, or unrecognized => info (safe)
		return finding.SeverityInfo
	}
}

func mapConfidence(ev *nucleiEvent) finding.Confidence {
	if ev.MatcherStatus {
		return finding.ConfidenceHigh
	}
	return finding.ConfidenceMedium
}

func mapCVSS(c nucleiClass) *finding.CVSS {
	if c.CVSSScore == 0 && strings.TrimSpace(c.CVSSMetrics) == "" {
		return nil
	}
	return &finding.CVSS{
		Version: cvssVersion(c.CVSSMetrics),
		Vector:  c.CVSSMetrics,
		Score:   c.CVSSScore,
	}
}

func cvssVersion(metrics string) string {
	m := strings.TrimSpace(metrics)
	if !strings.HasPrefix(strings.ToUpper(m), "CVSS:") {
		return ""
	}
	rest := m[len("CVSS:"):]
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		return rest[:i]
	}
	return rest
}

// methodFromRequest takes the HTTP method from the first line of the raw request
// (e.g. "POST /x HTTP/1.1" -> "POST"). Returns "" when it is not a known method,
// so Location.Method only holds a valid value (omitempty when empty).
func methodFromRequest(req string) string {
	req = strings.TrimSpace(req)
	if req == "" {
		return ""
	}
	line := req
	if i := strings.IndexAny(req, "\r\n"); i >= 0 {
		line = req[:i]
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return ""
	}
	switch m := strings.ToUpper(fields[0]); m {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT":
		return m
	}
	return ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func cleanList(in stringList) []string {
	var out []string
	for _, v := range in {
		if s := strings.TrimSpace(v); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "\n...[truncated]"
}
