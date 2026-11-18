package web

import (
	"net/url"
	"strings"
	"testing"
)

// A valid & in-scope OpenAPI spec must start a run (endpoints become targets)
// and produce findings — proving the spec → target expansion works.
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
	runID := runIDFrom(t, rec.Body.String()) // fails if it errors with "at least one target" instead
	waitRunDone(t, srv, runID)
	if b := do(t, srv, "GET", "/findings?program=apiscan", nil).Body.String(); !strings.Contains(b, "SSRF via fetch parameter") {
		t.Error("a scan from an OpenAPI spec must produce findings")
	}
}

func TestScanOpenAPIInvalidShowsError(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := do(t, srv, "POST", "/scan", url.Values{
		"program":  {"apiscan"},
		"in_scope": {"demo.test"},
		"targets":  {""},
		"seeds":    {""},
		"openapi":  {`{"openapi":"3.0.0","paths":{}}`}, // no paths → parse error
		"rps":      {"10"},
	})
	if !strings.Contains(rec.Body.String(), "OpenAPI/Swagger:") {
		t.Errorf("an invalid spec must show an OpenAPI error:\n%s", rec.Body.String())
	}
}
