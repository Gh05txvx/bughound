package nuclei

import "strings"

const redacted = "[REDACTED]"

// sensitiveHeaders adalah header yang nilainya wajib disensor sebelum bukti
// disimpan (BH-SPEC-FINDING: skema tidak pernah menyimpan secret mentah).
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

// sanitizeHTTP menyensor nilai header sensitif dari teks HTTP mentah
// (request/response), mempertahankan struktur baris agar bukti tetap terbaca.
// Menangani akhiran baris "\n" maupun "\r\n".
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
