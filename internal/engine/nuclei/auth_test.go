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
		t.Error("tanpa UseAuthHeaders tak boleh ada -H")
	}
	r.UseAuthHeaders([]string{hdr, "", "  "}) // elemen kosong diabaikan
	a := r.buildArgs("http://t")
	if !hasHeaderArg(a, hdr) {
		t.Errorf("buildArgs harus memuat -H %q: %v", hdr, a)
	}
	// hanya satu -H (elemen kosong tak ikut)
	n := 0
	for _, x := range a {
		if x == "-H" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("mau 1 -H, dapat %d: %v", n, a)
	}
}

func TestDASTRunnerAuthHeaders(t *testing.T) {
	hdr := "Authorization: Bearer xyz"
	r := &DASTRunner{proxyAddr: "127.0.0.1:1"}
	r.UseAuthHeaders([]string{hdr})
	if !hasHeaderArg(r.katanaArgs("http://t"), hdr) {
		t.Error("katanaArgs (crawl) harus memuat -H auth")
	}
	if !hasHeaderArg(r.nucleiArgsMode("f", ""), hdr) {
		t.Error("nucleiArgsMode (fuzz) harus memuat -H auth")
	}
}

// Scan berlogin tak boleh menjalankan template yang me-request route logout:
// nuclei jalan pertama di roster, jadi sesi mati untuk SEMUA engine sesudahnya.
func TestRunnerExcludesLogoutTemplates(t *testing.T) {
	dir := t.TempDir()
	for n, s := range map[string]string{
		"a.yaml": "id: a\nhttp:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/logout\"\n",
		"b.yaml": "id: b\nhttp:\n  - raw:\n      - |\n        GET /api/auth/signout HTTP/1.1\n        Host: {{Hostname}}\n",
		"c.yaml": "id: c\nhttp:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/admin\"\n",
		"d.yaml": "id: d\ninfo:\n  description: cek CSRF logout\nhttp:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/login\"\n",
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
		t.Errorf("tanpa auth tak boleh ada -exclude-templates: %s", e)
	}
	r.UseAuthHeaders([]string{"Cookie: s=1"})
	e := excl(r.buildArgs("http://t"))
	for _, n := range []string{"a.yaml", "b.yaml"} {
		if !strings.Contains(e, filepath.Join(dir, n)) {
			t.Errorf("template logout %s harus dikecualikan: %q", n, e)
		}
	}
	for _, n := range []string{"c.yaml", "d.yaml"} {
		if strings.Contains(e, n) {
			t.Errorf("template %s bukan request logout, tak boleh dikecualikan: %q", n, e)
		}
	}
}

// Scan berlogin: operasi logout di spec OpenAPI dibuang sebelum di-fuzz (Petstore
// punya GET /user/logout). YAML & JSON (indentasi tab) sama-sama terurai.
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
			t.Fatalf("spec sah harus terurai: %v", err)
		}
		var got map[string]any
		if err := yaml.Unmarshal(out, &got); err != nil {
			t.Fatalf("hasil bukan YAML sah: %v\n%s", err, out)
		}
		paths, _ := got["paths"].(map[string]any)
		if len(paths) != len(tc.keep) || got[tc.version] == nil {
			t.Errorf("mau paths %v + kunci %q utuh; dapat:\n%s", tc.keep, tc.version, out)
		}
		for _, k := range tc.keep {
			if paths[k] == nil {
				t.Errorf("path non-logout %s hilang:\n%s", k, out)
			}
		}
	}
	if _, err := withoutLogoutPaths([]byte("- bukan\n- mapping\n")); err == nil {
		t.Error("spec bukan mapping harus galat (pass OpenAPI dilewati, fail-closed)")
	}
}

// Crawl katana milik nuclei-dast: berlogin → -cos logout; tanpa login tak dibatasi.
func TestDASTKatanaSkipsLogoutWhenAuth(t *testing.T) {
	r := &DASTRunner{proxyAddr: "127.0.0.1:1"}
	if strings.Contains(strings.Join(r.katanaArgs("http://t"), " "), "-cos") {
		t.Error("tanpa auth, crawl tak boleh dibatasi -cos")
	}
	r.UseAuthHeaders([]string{"Cookie: s=1"})
	a, ok := r.katanaArgs("http://t"), false
	for i := 0; i+1 < len(a); i++ {
		ok = ok || (a[i] == "-cos" && a[i+1] == engine.LogoutPattern)
	}
	if !ok {
		t.Errorf("dengan auth, katana nuclei-dast wajib -cos %q; dapat %v", engine.LogoutPattern, a)
	}
}
