// Package nuclei menormalkan output nuclei (JSONL) ke Skema Temuan Seragam
// (BH-SPEC-FINDING) dan menyediakan engine mock untuk M0/E2E.
//
// Adapter ini tidak pernah menyimpan secret mentah: nilai header otentikasi di
// request/response disensor sebelum masuk evidence MAUPUN raw.
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

// stringList menerima nilai JSON berupa array string ATAU satu string
// (dipisah koma), karena versi nuclei berbeda menulis tags/reference/cwe
// dengan salah satu bentuk.
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
	TemplateID       string      `json:"template-id"`
	Type             string      `json:"type"`
	Host             string      `json:"host"`
	MatchedAt        string      `json:"matched-at"`
	Request          string      `json:"request"`
	Response         string      `json:"response"`
	IP               string      `json:"ip"`
	Timestamp        string      `json:"timestamp"`
	MatcherStatus    bool        `json:"matcher-status"`
	MatcherName      string      `json:"matcher-name"`
	ExtractedResults stringList  `json:"extracted-results"`
	Info             nucleiInfo  `json:"info"`
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

// Parse membaca output nuclei dalam format JSONL dan mengembalikan temuan
// ternormalkan. Baris kosong dan baris non-JSON (banner) dilewati; baris JSON
// yang rusak menghasilkan error.
func Parse(r io.Reader, program, runID string) ([]*finding.Finding, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024) // request/response bisa besar

	var out []*finding.Finding
	lineNo := 0
	for sc.Scan() {
		lineNo++
		b := bytes.TrimSpace(sc.Bytes())
		if len(b) == 0 || b[0] != '{' {
			continue
		}
		raw := make([]byte, len(b)) // Scanner memakai ulang buffer-nya
		copy(raw, b)

		var ev nucleiEvent
		if err := json.Unmarshal(raw, &ev); err != nil {
			return nil, fmt.Errorf("nuclei: baris %d bukan JSON valid: %w", lineNo, err)
		}
		f, err := mapEvent(&ev, raw, program, runID)
		if err != nil {
			return nil, fmt.Errorf("nuclei: baris %d: %w", lineNo, err)
		}
		out = append(out, f)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("nuclei: gagal membaca output: %w", err)
	}
	return out, nil
}

func mapEvent(ev *nucleiEvent, raw []byte, program, runID string) (*finding.Finding, error) {
	locURL := firstNonEmpty(ev.MatchedAt, ev.Host)
	if locURL == "" {
		return nil, errors.New("event tanpa matched-at/host")
	}

	// Sensor request/response SATU KALI; dipakai untuk evidence dan raw.
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
		Title:          firstNonEmpty(ev.Info.Name, ev.TemplateID, "temuan nuclei"),
		Description:    ev.Info.Description,
		Severity:       mapSeverity(ev.Info.Severity),
		Confidence:     mapConfidence(ev),
		CWE:            cleanList(ev.Info.Classification.CWEID),
		Tags:           cleanList(ev.Info.Tags),
		Location:       finding.Location{URL: locURL},
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

// sanitizeRaw mempertahankan seluruh field mentah nuclei tapi mengganti
// request/response dengan versi tersensor, agar raw pun tidak membawa secret.
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
	default: // info, unknown, kosong, atau tak dikenal => info (aman)
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
	return s[:max] + "\n...[dipotong]"
}
