package nuclei

import "strings"

const redacted = "[REDACTED]"

// sensitiveHeaders are headers whose values must be redacted before evidence is
// stored (BH-SPEC-FINDING: the schema never stores a raw secret).
var sensitiveHeaders = map[string]bool{
	"authorization":        true,
	"proxy-authorization":  true,
	"cookie":               true,
	"set-cookie":           true,
	"x-api-key":            true,
	"api-key":              true,
	"apikey":               true,
	"x-auth-token":         true,
	"x-session-token":      true,
	"x-csrf-token":         true,
	"x-amz-security-token": true,
	"authentication":       true,
}

// sanitizeHTTP redacts sensitive header values from raw HTTP text
// (request/response), keeping the line structure so the evidence stays readable.
// Handles both "\n" and "\r\n" line endings.
func sanitizeHTTP(text string) string {
	if text == "" {
		return ""
	}
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		cr := strings.HasSuffix(line, "\r")
		trimmed := strings.TrimSuffix(line, "\r")
		colon := strings.IndexByte(trimmed, ':')
		if colon <= 0 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(trimmed[:colon]))
		if !sensitiveHeaders[name] {
			continue
		}
		rebuilt := trimmed[:colon] + ": " + redacted
		if cr {
			rebuilt += "\r"
		}
		lines[i] = rebuilt
	}
	return strings.Join(lines, "\n")
}
