package dalfox

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"strings"

	"bughound/internal/finding"
)

// dalfoxPoC mencerminkan satu entri PoC pada output JSON dalfox (model.PoC di
// dalfox v2). Hanya field yang kita pakai yang didefinisikan; sisanya diabaikan.
type dalfoxPoC struct {
	Type        string `json:"type"`         // V=verified, R=reflected, G=grep/bav
	InjectType  string `json:"inject_type"`  // mis. "inHTML-URL", "inJS-double"
	Method      string `json:"method"`       // GET/POST
	Data        string `json:"data"`         // URL PoC (payload tertanam)
	Param       string `json:"param"`        // parameter terdampak
	Payload     string `json:"payload"`      // payload yang dikirim
	Evidence    string `json:"evidence"`     // cuplikan bukti
	CWE         string `json:"cwe"`          // mis. "CWE-79"
	Severity    string `json:"severity"`     // High/Medium/Low/Info
	MessageStr  string `json:"message_str"`  // deskripsi (opsional)
	RawRequest  string `json:"raw_request"`  // HTTP request mentah (opsional)
	RawResponse string `json:"raw_response"` // HTTP response mentah (opsional)
}

// dalfoxResult membungkus daftar PoC bila dalfox menulis objek Result penuh.
type dalfoxResult struct {
	PoCs []dalfoxPoC `json:"pocs"`
}

// Parse menormalkan output JSON dalfox ke Skema Temuan Seragam (BH-SPEC-FINDING).
// Toleran pada tiga bentuk yang mungkin dipancarkan dalfox: objek Result
// (`{"pocs":[...]}`), array PoC (`[...]`), atau JSONL (satu objek PoC per baris).
// program/run_id/target diisi di sini; store mengisi id/dedup_key/schema/created.
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

// extractPoCs mengurai daftar PoC dari output dalfox secara toleran terhadap
// bentuk (Result object / array / JSONL). Baris/entri yang tak valid dilewati.
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
		// Satu objek PoC tunggal.
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
	// JSONL: satu objek per baris (mode stream dalfox).
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

// mapPoC memetakan satu PoC dalfox ke Finding. Mengembalikan nil bila PoC kosong.
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

// buildEvidence menyusun Evidence dari PoC, menyensor header sensitif pada
// request/response mentah (BH-SPEC-FINDING: skema tak pernah menyimpan secret
// mentah). Mengembalikan nil bila tak ada bahan bukti.
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

// sensitiveHeaders adalah header yang nilainya disensor dari evidence.
var sensitiveHeaders = []string{"authorization:", "proxy-authorization:", "cookie:", "set-cookie:", "x-api-key:", "x-auth-token:"}

// redactHTTP menyensor NILAI header sensitif (Authorization/Cookie/dst.) pada
// teks HTTP mentah, mempertahankan nama header agar struktur tetap terbaca.
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

// mapType menormalkan tipe temuan dari CWE (dalfox mengisi CWE spesifik untuk
// temuan non-XSS dari BAV), lalu fallback ke "xss" (dalfox berfokus XSS).
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

// mapSeverity memetakan severity dalfox (High/Medium/Low/Info) ke skema.
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

// mapConfidence memetakan tipe PoC dalfox ke confidence: V(erified)=high (lolos
// verifikasi headless), R(eflected)=medium, G(rep/BAV)=low.
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

// buildTitle menyusun judul ringkas dari tipe + level verifikasi + parameter.
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
	if v := map[string]string{"V": "terverifikasi", "R": "refleksi", "G": "heuristik"}[strings.ToUpper(strings.TrimSpace(pocType))]; v != "" {
		label += " (" + v + ")"
	}
	if p := strings.TrimSpace(param); p != "" {
		label += " pada parameter `" + p + "`"
	}
	return truncate(label, 160)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
