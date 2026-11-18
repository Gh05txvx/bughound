package ffuf

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeAPIRoutes(t *testing.T) {
	raw := []byte(`# comment
/api/v1/bulklog
/api/v1/bulklog
/rest/products/search?q=1
/graphql
/with space/x
/wild*card
no-leading-slash
/

`)
	got := normalizeAPIRoutes(raw, 100)
	want := []string{"api/v1/bulklog", "rest/products/search", "graphql", "no-leading-slash"}
	if len(got) != len(want) {
		t.Fatalf("wrong path count: got %v (len %d), want %v", got, len(got), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("path[%d]=%q, want %q", i, got[i], want[i])
		}
	}
}

func TestNormalizeAPIRoutesMaxCap(t *testing.T) {
	var b []byte
	for i := 0; i < 50; i++ {
		b = append(b, []byte("/p"+string(rune('a'+i%26))+string(rune('0'+i/26))+"\n")...)
	}
	got := normalizeAPIRoutes(b, 10)
	if len(got) != 10 {
		t.Fatalf("max cap must be 10; got %d", len(got))
	}
}

// apiRoutePaths is gated on APIRoutes AND proxyAddr: without either one, nil
// (no path amplification without a scope-enforced proxy).
func TestAPIRoutePathsGating(t *testing.T) {
	dir := t.TempDir()
	wl := filepath.Join(dir, "apiroutes.txt")
	if err := os.WriteFile(wl, []byte("/api/v1/x\n/api/v1/y\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BUGHOUND_API_WORDLIST", wl)

	// APIRoutes=false returns nil even when a proxy is set.
	off := &Runner{}
	off.UseProxy("127.0.0.1:1")
	if got := off.apiRoutePaths(); got != nil {
		t.Errorf("APIRoutes=false must be nil; got %v", got)
	}

	// APIRoutes=true but without a proxy returns nil (fail-safe).
	noProxy := &Runner{APIRoutes: true}
	if got := noProxy.apiRoutePaths(); got != nil {
		t.Errorf("without a proxy must be nil; got %v", got)
	}

	// APIRoutes=true + proxy reads the file (env override), paths in FUZZ form.
	on := &Runner{APIRoutes: true}
	on.UseProxy("127.0.0.1:1")
	got := on.apiRoutePaths()
	if len(got) != 2 || got[0] != "api/v1/x" || got[1] != "api/v1/y" {
		t.Errorf("must read 2 FUZZ paths from env; got %v", got)
	}
}

// A missing wordlist file returns nil (best-effort), not an error or panic.
func TestAPIRoutePathsAbsent(t *testing.T) {
	t.Setenv("BUGHOUND_API_WORDLIST", filepath.Join(t.TempDir(), "does-not-exist.txt"))
	r := &Runner{APIRoutes: true}
	r.UseProxy("127.0.0.1:1")
	if got := r.apiRoutePaths(); got != nil {
		t.Errorf("missing file must be nil; got %v", got)
	}
}
