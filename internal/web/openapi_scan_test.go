package web

import (
	"net/url"
	"strings"
	"testing"
)

// Spec OpenAPI yang valid & in-scope harus memulai run (endpoint jadi target)
// dan menghasilkan temuan — membuktikan ekspansi spec → target berjalan.
func TestScanOpenAPIExpandsEndpoints(t *testing.T) {
	srv, _ := newTestServer(t)
	spec := `{"openapi":"3.0.0","servers":[{"url":"https://api.demo.test"}],"paths":{"/users":{"get":{}},"/orders/{id}":{"get":{}}}}`
	rec := do(t, srv, "POST", "/scan", url.Values{
		"program":  {"apiscan"},
		"in_scope": {"demo.test\n*.demo.test"},
		"targets":  {""},
		"seeds":    {""},
		"openapi":  {spec},
		"rps":      {"10"},
	})
	runID := runIDFrom(t, rec.Body.String()) // gagal bila malah error "isi minimal satu target"
	waitRunDone(t, srv, runID)
	if b := do(t, srv, "GET", "/findings?program=apiscan", nil).Body.String(); !strings.Contains(b, "SSRF via fetch parameter") {
		t.Error("scan dari spec OpenAPI harus menghasilkan temuan")
	}
}

func TestScanOpenAPIInvalidShowsError(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := do(t, srv, "POST", "/scan", url.Values{
		"program":  {"apiscan"},
		"in_scope": {"demo.test"},
		"targets":  {""},
		"seeds":    {""},
		"openapi":  {`{"openapi":"3.0.0","paths":{}}`}, // tanpa paths → error parse
		"rps":      {"10"},
	})
	if !strings.Contains(rec.Body.String(), "OpenAPI/Swagger:") {
		t.Errorf("spec tak valid harus menampilkan error OpenAPI:\n%s", rec.Body.String())
	}
}
