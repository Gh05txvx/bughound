package finding

import (
	"strings"
	"testing"
)

func TestEvidenceRedactHeaders(t *testing.T) {
	e := &Evidence{
		Request:         "GET /a HTTP/1.1\r\nHost: h\r\nCookie: session=SECRET; x=1\r\nAuthorization: Bearer TOKEN\r\nAccept: */*\r\n\r\n",
		ResponseExcerpt: "HTTP/1.1 200 OK\r\nSet-Cookie: s=NEW\r\n",
	}
	e.RedactHeaders([]string{"Cookie", "Authorization"})
	if strings.Contains(e.Request, "SECRET") || strings.Contains(e.Request, "TOKEN") {
		t.Errorf("nilai header auth harus tersensor: %q", e.Request)
	}
	if !strings.Contains(e.Request, "Cookie: [REDACTED]") || !strings.Contains(e.Request, "Authorization: [REDACTED]") {
		t.Errorf("nama header harus tetap + nilai [REDACTED]: %q", e.Request)
	}
	for _, keep := range []string{"GET /a HTTP/1.1", "Host: h", "Accept: */*"} {
		if !strings.Contains(e.Request, keep) {
			t.Errorf("baris non-target harus utuh (%q): %q", keep, e.Request)
		}
	}
	// Hanya nama yang diminta yang diredaksi; Set-Cookie di response tak diminta.
	if !strings.Contains(e.ResponseExcerpt, "Set-Cookie: s=NEW") {
		t.Errorf("response: hanya nama diminta yang diredaksi: %q", e.ResponseExcerpt)
	}
}

func TestEvidenceRedactHeadersCaseInsensitiveCRLF(t *testing.T) {
	e := &Evidence{Request: "cookie: a=b\r\nCOOKIE: c=d\n"}
	e.RedactHeaders([]string{"Cookie"})
	if strings.Contains(e.Request, "a=b") || strings.Contains(e.Request, "c=d") {
		t.Errorf("cocok case-insensitive: %q", e.Request)
	}
	if first, _, _ := strings.Cut(e.Request, "\n"); !strings.HasSuffix(first, "\r") {
		t.Errorf("CRLF harus dipertahankan: %q", e.Request)
	}
}

func TestEvidenceRedactHeadersNoop(t *testing.T) {
	orig := "Cookie: keep=me\r\n"
	e := &Evidence{Request: orig}
	e.RedactHeaders(nil) // tanpa names → tak berubah
	if e.Request != orig {
		t.Errorf("tanpa names tak boleh berubah; dapat %q", e.Request)
	}
	var ne *Evidence
	ne.RedactHeaders([]string{"Cookie"}) // nil receiver tak boleh panik
}
