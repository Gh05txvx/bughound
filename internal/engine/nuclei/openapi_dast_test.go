package nuclei

import (
	"context"
	"strings"
	"testing"
)

// openapi mode adds -input-mode + -skip-format-validation, and still carries the
// safety arguments (non-destructive) plus -dast.
func TestNucleiArgsOpenAPIMode(t *testing.T) {
	r := &DASTRunner{RateLimit: 20, proxyAddr: "127.0.0.1:9000"}
	a := strings.Join(r.nucleiArgsMode("/tmp/spec.yaml", "openapi"), " ")
	for _, want := range []string{"-dast", "-input-mode openapi", "-skip-format-validation", "-list /tmp/spec.yaml", "-no-interactsh"} {
		if !strings.Contains(a, want) {
			t.Errorf("openapi args do not contain %q; got: %s", want, a)
		}
	}
	// Non-stealth: no -required-only.
	if strings.Contains(a, "-required-only") {
		t.Errorf("non-stealth must not have -required-only; got: %s", a)
	}
}

// Stealth + openapi: add -required-only (fewer requests).
func TestNucleiArgsOpenAPIStealthRequiredOnly(t *testing.T) {
	r := &DASTRunner{RateLimit: 20, proxyAddr: "x:1", Safety: Safety{Stealth: true}}
	a := strings.Join(r.nucleiArgsMode("spec", "openapi"), " ")
	if !strings.Contains(a, "-required-only") {
		t.Errorf("stealth openapi must have -required-only; got: %s", a)
	}
}

// list mode (default) does not inject the openapi flags.
func TestNucleiArgsListModeNoOpenAPI(t *testing.T) {
	r := &DASTRunner{RateLimit: 20, proxyAddr: "x:1"}
	a := strings.Join(r.nucleiArgs("/tmp/list.txt"), " ")
	if strings.Contains(a, "-input-mode") || strings.Contains(a, "-required-only") {
		t.Errorf("list mode must not have openapi flags; got: %s", a)
	}
}

func TestDetectSpecMode(t *testing.T) {
	cases := map[string]string{
		`{"openapi":"3.0.0","info":{}}`: "openapi",
		`{"swagger":"2.0","info":{}}`:   "swagger",
		"swagger: \"2.0\"\ninfo: {}":    "swagger",
		"openapi: 3.0.1\ninfo: {}":      "openapi",
		`{"paths":{}}`:                  "openapi", // default when ambiguous
	}
	for spec, want := range cases {
		if got := detectSpecMode([]byte(spec)); got != want {
			t.Errorf("detectSpecMode(%q) = %q, want %q", spec, got, want)
		}
	}
}

// UseOpenAPISpec sets the spec; Scan without a proxy is still nil (fail-safe) even
// with a spec attached, since there is no connection without an egress proxy.
func TestUseOpenAPISpecNoProxyStillSafe(t *testing.T) {
	r := &DASTRunner{}
	r.UseOpenAPISpec([]byte(`{"openapi":"3.0.0"}`))
	fs, err := r.Scan(context.Background(), "http://t/", "p", "run1")
	if fs != nil || err != nil {
		t.Fatalf("without a proxy must be nil,nil even with a spec; got %v,%v", fs, err)
	}
}
