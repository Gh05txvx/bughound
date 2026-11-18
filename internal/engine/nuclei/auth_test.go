package nuclei

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"bughound/internal/engine"
)

func hasHeaderArg(args []string, hdr string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-H" && args[i+1] == hdr {
			return true
		}
	}
	return false
}

func TestRunnerBuildArgsAuthHeaders(t *testing.T) {
	hdr := "Cookie: session=abc"
	r := &Runner{}
	if hasHeaderArg(r.buildArgs("http://t"), hdr) {
		t.Error("without UseAuthHeaders there must be no -H")
	}
	r.UseAuthHeaders([]string{hdr, "", "  "}) // empty elements are ignored
	a := r.buildArgs("http://t")
	if !hasHeaderArg(a, hdr) {
		t.Errorf("buildArgs must contain -H %q: %v", hdr, a)
	}
	// only one -H (empty elements excluded)
	n := 0
	for _, x := range a {
		if x == "-H" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("want 1 -H, got %d: %v", n, a)
	}
}

func TestDASTRunnerAuthHeaders(t *testing.T) {
	hdr := "Authorization: Bearer xyz"
	r := &DASTRunner{proxyAddr: "127.0.0.1:1"}
	r.UseAuthHeaders([]string{hdr})
	if !hasHeaderArg(r.katanaArgs("http://t"), hdr) {
		t.Error("katanaArgs (crawl) must contain the auth -H")
	}
	if !hasHeaderArg(r.nucleiArgsMode("f", ""), hdr) {
		t.Error("nucleiArgsMode (fuzz) must contain the auth -H")
	}
}

// An authenticated scan must not run a template that requests a logout route:
// nuclei runs first in the roster, so the session dies for ALL engines after it.
func TestRunnerExcludesLogoutTemplates(t *testing.T) {
	dir := t.TempDir()
	for n, s := range map[string]string{
		"a.yaml": "id: a\nhttp:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/logout\"\n",
		"b.yaml": "id: b\nhttp:\n  - raw:\n      - |\n        GET /api/auth/signout HTTP/1.1\n        Host: {{Hostname}}\n",
		"c.yaml": "id: c\nhttp:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/admin\"\n",
		"d.yaml": "id: d\ninfo:\n  description: check CSRF logout\nhttp:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/login\"\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	excl := func(a []string) string {
		for i := 0; i+1 < len(a); i++ {
			if a[i] == "-exclude-templates" {
				return a[i+1]
			}
		}
		return ""
	}
	r := &Runner{TemplatesDir: dir}
	if e := excl(r.buildArgs("http://t")); e != "" {
		t.Errorf("without auth there must be no -exclude-templates: %s", e)
	}
	r.UseAuthHeaders([]string{"Cookie: s=1"})
	e := excl(r.buildArgs("http://t"))
	for _, n := range []string{"a.yaml", "b.yaml"} {
		if !strings.Contains(e, filepath.Join(dir, n)) {
			t.Errorf("logout template %s must be excluded: %q", n, e)
		}
	}
	for _, n := range []string{"c.yaml", "d.yaml"} {
		if strings.Contains(e, n) {
			t.Errorf("template %s is not a logout request, must not be excluded: %q", n, e)
		}
	}
}

// Authenticated scan: logout operations in the OpenAPI spec are dropped before
// fuzzing (Petstore has GET /user/logout). YAML & JSON (tab-indented) both parse.
func TestWithoutLogoutPaths(t *testing.T) {
	for _, tc := range []struct {
		spec, version string
		keep          []string
	}{
		{"swagger: \"2.0\"\nhost: t.test\npaths:\n  /user/login:\n    get: {}\n  /user/logout:\n    get: {}\n  /pet:\n    post: {}\n",
			"swagger", []string{"/user/login", "/pet"}},
		{"{\n\t\"openapi\": \"3.0.0\",\n\t\"paths\": {\n\t\t\"/api/auth/sign-out\": {\"post\": {}},\n\t\t\"/api/items\": {\"get\": {}}\n\t}\n}",
			"openapi", []string{"/api/items"}},
	} {
		out, err := withoutLogoutPaths([]byte(tc.spec))
		if err != nil {
			t.Fatalf("a valid spec must parse: %v", err)
		}
		var got map[string]any
		if err := yaml.Unmarshal(out, &got); err != nil {
			t.Fatalf("result is not valid YAML: %v\n%s", err, out)
		}
		paths, _ := got["paths"].(map[string]any)
		if len(paths) != len(tc.keep) || got[tc.version] == nil {
			t.Errorf("want paths %v + key %q intact; got:\n%s", tc.keep, tc.version, out)
		}
		for _, k := range tc.keep {
			if paths[k] == nil {
				t.Errorf("non-logout path %s is missing:\n%s", k, out)
			}
		}
	}
	if _, err := withoutLogoutPaths([]byte("- not\n- mapping\n")); err == nil {
		t.Error("a non-mapping spec must error (the OpenAPI pass is skipped, fail-closed)")
	}
}

// nuclei-dast's katana crawl: authenticated -> -cos logout; without login it is not restricted.
func TestDASTKatanaSkipsLogoutWhenAuth(t *testing.T) {
	r := &DASTRunner{proxyAddr: "127.0.0.1:1"}
	if strings.Contains(strings.Join(r.katanaArgs("http://t"), " "), "-cos") {
		t.Error("without auth, the crawl must not be restricted by -cos")
	}
	r.UseAuthHeaders([]string{"Cookie: s=1"})
	a, ok := r.katanaArgs("http://t"), false
	for i := 0; i+1 < len(a); i++ {
		ok = ok || (a[i] == "-cos" && a[i+1] == engine.LogoutPattern)
	}
	if !ok {
		t.Errorf("with auth, nuclei-dast's katana must have -cos %q; got %v", engine.LogoutPattern, a)
	}
}
