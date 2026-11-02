package ffuf

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLooksLikeSpec(t *testing.T) {
	cases := []struct {
		body string
		want bool
	}{
		{`{"openapi":"3.0.0","paths":{"/a":{}}}`, true},
		{"swagger: \"2.0\"\npaths:\n  /a: {}", true},
		{"<!doctype html><html>SPA catch-all</html>", false},
		{"   <html>", false},
		{"", false},
		{`{"openapi":"3.0.0"}`, false}, // tanpa paths -> bukan spec yang berguna
	}
	for _, c := range cases {
		if got := looksLikeSpec([]byte(c.body)); got != c.want {
			t.Errorf("looksLikeSpec(%.30q) = %v; mau %v", c.body, got, c.want)
		}
	}
}

func TestExtractSwaggerDoc(t *testing.T) {
	js := `window.onload = function() {
  var options = {"swaggerDoc":{"openapi":"3.0.0","paths":{"/orders":{"get":{}}}},"customOptions":{}};
  window.ui = SwaggerUIBundle(options);
};`
	got := string(extractSwaggerDoc([]byte(js)))
	want := `{"openapi":"3.0.0","paths":{"/orders":{"get":{}}}}`
	if got != want {
		t.Fatalf("extractSwaggerDoc = %q; mau %q", got, want)
	}
	// Kurung di dalam string tak boleh mengacaukan penghitungan.
	tricky := `x "swaggerDoc": {"a":"}{","paths":{}} rest`
	if g := string(extractSwaggerDoc([]byte(tricky))); g != `{"a":"}{","paths":{}}` {
		t.Errorf("extractSwaggerDoc (string berisi kurung) = %q", g)
	}
	if extractSwaggerDoc([]byte("tak ada doc")) != nil {
		t.Error("tanpa swaggerDoc harus nil")
	}
}

func TestEndpointPaths(t *testing.T) {
	in := []string{
		"http://t.test/rest/products/search",
		"http://t.test/api/Users",
		"http://t.test/rest/products/search", // duplikat
		"http://OTHER.test/b2b/v2/orders",    // host beda -> path tetap dipakai
	}
	got := endpointPaths(in)
	want := map[string]bool{"rest/products/search": true, "api/Users": true, "b2b/v2/orders": true}
	if len(got) != len(want) {
		t.Fatalf("endpointPaths = %v; mau 3 unik", got)
	}
	for _, p := range got {
		if !want[p] {
			t.Errorf("path tak terduga: %q", p)
		}
	}
}

func TestSpecPathsNoProxyNoFetch(t *testing.T) {
	r := &Runner{} // proxyAddr kosong
	if got := r.specPaths(context.Background(), "http://demo.test"); got != nil {
		t.Fatalf("tanpa proxy tak boleh fetch; dapat %v", got)
	}
}

func TestSpecPathsFromStandaloneJSON(t *testing.T) {
	spec := `{"openapi":"3.0.0","servers":[{"url":"/"}],"paths":{"/rest/products/search":{"get":{}},"/api/Users":{"get":{}}}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/openapi.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(spec))
			return
		}
		http.NotFound(w, req)
	}))
	defer srv.Close()
	got := specPathsFrom(context.Background(), srv.Client(), srv.URL)
	set := map[string]bool{}
	for _, p := range got {
		set[p] = true
	}
	if !set["rest/products/search"] || !set["api/Users"] {
		t.Fatalf("spec standalone harus menghasilkan endpoint; dapat %v", got)
	}
}

func TestSpecPathsFromSwaggerUIInit(t *testing.T) {
	js := `window.onload=function(){var options={"swaggerDoc":{"openapi":"3.0.0","servers":[{"url":"/b2b/v2"}],"paths":{"/orders":{"get":{}}}}};};`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/api-docs/swagger-ui-init.js" {
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(js))
			return
		}
		http.NotFound(w, req) // /openapi.json dll 404 -> jatuh ke init.js
	}))
	defer srv.Close()
	got := specPathsFrom(context.Background(), srv.Client(), srv.URL)
	if strings.Join(got, ",") != "b2b/v2/orders" {
		t.Fatalf("swagger-ui-init.js harus menghasilkan b2b/v2/orders; dapat %v", got)
	}
}

// TestSpecPathsFromSPACatchAll: server SPA yang membalas HTML untuk SEMUA path
// (termasuk /openapi.json) tak boleh salah di-parse jadi spec.
func TestSpecPathsFromSPACatchAll(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<!doctype html><html><body>SPA</body></html>"))
	}))
	defer srv.Close()
	if got := specPathsFrom(context.Background(), srv.Client(), srv.URL); got != nil {
		t.Fatalf("catch-all HTML tak boleh jadi endpoint; dapat %v", got)
	}
}
