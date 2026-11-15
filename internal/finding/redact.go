package finding

import "strings"

// RedactHeaders menyensor NILAI header bernama names (case-insensitive) dari
// setiap field evidence tekstual, mengganti "Nama: <nilai>" menjadi
// "Nama: [REDACTED]". Nama header & struktur request lain dipertahankan agar
// evidence tetap berguna untuk verifikasi manual (mis. diputar ulang di Burp,
// di mana hunter memasang sesinya sendiri).
//
// Dipakai saat scan membawa header autentikasi (Lever 1): engine mencatat
// request lengkap termasuk header yang disuntikkan, jadi kredensial sesi bisa
// ikut ke evidence. Redaksi ini memastikan secret tak pernah tersimpan di
// evidence/report (Prinsip #5: secret tak bocor ke log/respons/report).
// names = nama header yang disuntikkan (mis. "Cookie", "Authorization").
func (e *Evidence) RedactHeaders(names []string) {
	if e == nil || len(names) == 0 {
		return
	}
	e.Request = redactHeaderLines(e.Request, names)
	e.ResponseExcerpt = redactHeaderLines(e.ResponseExcerpt, names)
	e.Payload = redactHeaderLines(e.Payload, names)
	e.Matched = redactHeaderLines(e.Matched, names)
}

// redactHeaderLines menyensor nilai pada baris yang namanya (sebelum ':')
// cocok salah satu names. Hanya baris bergaya header "Nama: nilai" yang
// terpengaruh; baris lain (request-line, body) utuh. CRLF dipertahankan.
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
