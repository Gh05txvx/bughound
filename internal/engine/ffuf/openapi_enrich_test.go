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
		{`{"openapi":"3.0.0"}`, false}, // no paths -> not a useful spec
	}
	for _, c := range cases {
		if got := looksLikeSpec([]byte(c.body)); got != c.want {
			t.Errorf("looksLikeSpec(%.30q) = %v; want %v", c.body, got, c.want)
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
		t.Fatalf("extractSwaggerDoc = %q; want %q", got, want)
	}
	// Braces inside a string must not throw off the counting.
	tricky := `x "swaggerDoc": {"a":"}{","paths":{}} rest`
	if g := string(extractSwaggerDoc([]byte(tricky))); g != `{"a":"}{","paths":{}}` {
		t.Errorf("extractSwaggerDoc (string containing braces) = %q", g)
	}
	if extractSwaggerDoc([]byte("no doc")) != nil {
		t.Error("without swaggerDoc must be nil")
	}
}

func TestEndpointPaths(t *testing.T) {
	in := []string{
		"http://t.test/rest/products/search",
		"http://t.test/api/Users",
		"http://t.test/rest/products/search", // duplicate
		"http://OTHER.test/b2b/v2/orders",    // different host -> path still used
	}
	got := endpointPaths(in)
	want := map[string]bool{"rest/products/search": true, "api/Users": true, "b2b/v2/orders": true}
	if len(got) != len(want) {
		t.Fatalf("endpointPaths = %v; want 3 unique", got)
	}
	for _, p := range got {
		if !want[p] {
			t.Errorf("unexpected path: %q", p)
		}
	}
}

func TestSpecPathsNoProxyNoFetch(t *testing.T) {
	r := &Runner{} // proxyAddr empty
	if got := r.specPaths(context.Background(), "http://demo.test"); got != nil {
		t.Fatalf("without a proxy there must be no fetch; got %v", got)
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
		t.Fatalf("a standalone spec must yield endpoints; got %v", got)
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
		http.NotFound(w, req) // /openapi.json etc 404 -> fall through to init.js
	}))
	defer srv.Close()
	got := specPathsFrom(context.Background(), srv.Client(), srv.URL)
	if strings.Join(got, ",") != "b2b/v2/orders" {
		t.Fatalf("swagger-ui-init.js must yield b2b/v2/orders; got %v", got)
	}
}

// TestSpecPathsFromSPACatchAll: an SPA server that answers HTML for EVERY path
// (including /openapi.json) must not be mis-parsed as a spec.
func TestSpecPathsFromSPACatchAll(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<!doctype html><html><body>SPA</body></html>"))
	}))
	defer srv.Close()
	if got := specPathsFrom(context.Background(), srv.Client(), srv.URL); got != nil {
		t.Fatalf("catch-all HTML must not become an endpoint; got %v", got)
	}
}
