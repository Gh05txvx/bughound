package finding

import "strings"

// RedactHeaders redacts the VALUE of the headers in names (case-insensitive)
// from every textual evidence field, turning "Name: <value>" into
// "Name: [REDACTED]". The header name and the rest of the request structure
// are kept so the evidence stays useful for manual verification (e.g. replayed
// in Burp, where the hunter supplies their own session).
//
// It is used when a scan carries authentication headers (Lever 1): engines
// record the full request including the injected headers, so session
// credentials can end up in the evidence. This redaction makes sure a secret
// is never stored in evidence or reports (Principle #5: secrets do not leak to
// logs/responses/reports). names = the injected header names (e.g. "Cookie",
// "Authorization").
func (e *Evidence) RedactHeaders(names []string) {
	if e == nil || len(names) == 0 {
		return
	}
	e.Request = redactHeaderLines(e.Request, names)
	e.ResponseExcerpt = redactHeaderLines(e.ResponseExcerpt, names)
	e.Payload = redactHeaderLines(e.Payload, names)
	e.Matched = redactHeaderLines(e.Matched, names)
}

// redactHeaderLines redacts the value on lines whose name (before ':') matches
// one of names. Only header-style "Name: value" lines are affected; other lines
// (request line, body) are left intact. CRLF is preserved.
func redactHeaderLines(s string, names []string) string {
	if s == "" {
		return s
	}
	lines := strings.Split(s, "\n")
	for i, ln := range lines {
		name, _, ok := strings.Cut(ln, ":")
		if !ok {
			continue
		}
		trimmed := strings.TrimSpace(name)
		if trimmed == "" {
			continue
		}
		for _, want := range names {
			if strings.EqualFold(trimmed, strings.TrimSpace(want)) {
				cr := ""
				if strings.HasSuffix(ln, "\r") {
					cr = "\r"
				}
				lines[i] = name + ": [REDACTED]" + cr
				break
			}
		}
	}
	return strings.Join(lines, "\n")
}
