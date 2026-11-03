package nuclei

import (
	"context"
	"strings"
	"testing"
)

// Mode openapi menambah -input-mode + -skip-format-validation, dan tetap membawa
// argumen keamanan (non-destruktif) serta -dast.
func TestNucleiArgsOpenAPIMode(t *testing.T) {
	r := &DASTRunner{RateLimit: 20, proxyAddr: "127.0.0.1:9000"}
	a := strings.Join(r.nucleiArgsMode("/tmp/spec.yaml", "openapi"), " ")
	for _, want := range []string{"-dast", "-input-mode openapi", "-skip-format-validation", "-list /tmp/spec.yaml", "-no-interactsh"} {
		if !strings.Contains(a, want) {
			t.Errorf("openapi args tak memuat %q; got: %s", want, a)
		}
	}
	// Non-stealth: tanpa -required-only.
	if strings.Contains(a, "-required-only") {
		t.Errorf("non-stealth tak boleh -required-only; got: %s", a)
	}
}

// Stealth + openapi: tambah -required-only (lebih sedikit request).
func TestNucleiArgsOpenAPIStealthRequiredOnly(t *testing.T) {
	r := &DASTRunner{RateLimit: 20, proxyAddr: "x:1", Safety: Safety{Stealth: true}}
	a := strings.Join(r.nucleiArgsMode("spec", "openapi"), " ")
	if !strings.Contains(a, "-required-only") {
		t.Errorf("stealth openapi harus -required-only; got: %s", a)
	}
}

// Mode list (default) tak menyuntik flag openapi.
func TestNucleiArgsListModeNoOpenAPI(t *testing.T) {
	r := &DASTRunner{RateLimit: 20, proxyAddr: "x:1"}
	a := strings.Join(r.nucleiArgs("/tmp/list.txt"), " ")
	if strings.Contains(a, "-input-mode") || strings.Contains(a, "-required-only") {
		t.Errorf("mode list tak boleh ada flag openapi; got: %s", a)
	}
}

func TestDetectSpecMode(t *testing.T) {
	cases := map[string]string{
		`{"openapi":"3.0.0","info":{}}`: "openapi",
		`{"swagger":"2.0","info":{}}`:   "swagger",
		"swagger: \"2.0\"\ninfo: {}":    "swagger",
		"openapi: 3.0.1\ninfo: {}":      "openapi",
		`{"paths":{}}`:                  "openapi", // default bila ambigu
	}
	for spec, want := range cases {
		if got := detectSpecMode([]byte(spec)); got != want {
			t.Errorf("detectSpecMode(%q) = %q, mau %q", spec, got, want)
		}
	}
}

// UseOpenAPISpec menyetel spec; Scan tanpa proxy tetap nil (fail-safe) walau spec
// terpasang — tak ada koneksi tanpa proxy egress.
func TestUseOpenAPISpecNoProxyStillSafe(t *testing.T) {
	r := &DASTRunner{}
	r.UseOpenAPISpec([]byte(`{"openapi":"3.0.0"}`))
	fs, err := r.Scan(context.Background(), "http://t/", "p", "run1")
	if fs != nil || err != nil {
		t.Fatalf("tanpa proxy harus nil,nil walau ada spec; dapat %v,%v", fs, err)
	}
}
