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
		t.Errorf("the auth header value must be redacted: %q", e.Request)
	}
	if !strings.Contains(e.Request, "Cookie: [REDACTED]") || !strings.Contains(e.Request, "Authorization: [REDACTED]") {
		t.Errorf("the header name must stay, with the value [REDACTED]: %q", e.Request)
	}
	for _, keep := range []string{"GET /a HTTP/1.1", "Host: h", "Accept: */*"} {
		if !strings.Contains(e.Request, keep) {
			t.Errorf("non-target lines must be intact (%q): %q", keep, e.Request)
		}
	}
	// Only the requested names are redacted; Set-Cookie in the response was not requested.
	if !strings.Contains(e.ResponseExcerpt, "Set-Cookie: s=NEW") {
		t.Errorf("response: only the requested names are redacted: %q", e.ResponseExcerpt)
	}
}

func TestEvidenceRedactHeadersCaseInsensitiveCRLF(t *testing.T) {
	e := &Evidence{Request: "cookie: a=b\r\nCOOKIE: c=d\n"}
	e.RedactHeaders([]string{"Cookie"})
	if strings.Contains(e.Request, "a=b") || strings.Contains(e.Request, "c=d") {
		t.Errorf("case-insensitive match: %q", e.Request)
	}
	if first, _, _ := strings.Cut(e.Request, "\n"); !strings.HasSuffix(first, "\r") {
		t.Errorf("CRLF must be preserved: %q", e.Request)
	}
}

func TestEvidenceRedactHeadersNoop(t *testing.T) {
	orig := "Cookie: keep=me\r\n"
	e := &Evidence{Request: orig}
	e.RedactHeaders(nil) // no names → unchanged
	if e.Request != orig {
		t.Errorf("without names nothing must change; got %q", e.Request)
	}
	var ne *Evidence
	ne.RedactHeaders([]string{"Cookie"}) // a nil receiver must not panic
}
