package ffuf

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeAPIRoutes(t *testing.T) {
	raw := []byte(`# komentar
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
		t.Fatalf("jumlah path salah: got %v (len %d), want %v", got, len(got), want)
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
		t.Fatalf("cap max harus 10; dapat %d", len(got))
	}
}

// apiRoutePaths di-gate pada APIRoutes DAN proxyAddr: tanpa salah satunya, nil
// (tak ada amplifikasi path tanpa proxy scope-enforced).
func TestAPIRoutePathsGating(t *testing.T) {
	dir := t.TempDir()
	wl := filepath.Join(dir, "apiroutes.txt")
	if err := os.WriteFile(wl, []byte("/api/v1/x\n/api/v1/y\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BUGHOUND_API_WORDLIST", wl)

	// APIRoutes=false → nil meski proxy diset.
	off := &Runner{}
	off.UseProxy("127.0.0.1:1")
	if got := off.apiRoutePaths(); got != nil {
		t.Errorf("APIRoutes=false harus nil; dapat %v", got)
	}

	// APIRoutes=true tapi tanpa proxy → nil (fail-safe).
	noProxy := &Runner{APIRoutes: true}
	if got := noProxy.apiRoutePaths(); got != nil {
		t.Errorf("tanpa proxy harus nil; dapat %v", got)
	}

	// APIRoutes=true + proxy → baca berkas (env override), path bentuk FUZZ.
	on := &Runner{APIRoutes: true}
	on.UseProxy("127.0.0.1:1")
	got := on.apiRoutePaths()
	if len(got) != 2 || got[0] != "api/v1/x" || got[1] != "api/v1/y" {
		t.Errorf("harus baca 2 path FUZZ dari env; dapat %v", got)
	}
}

// Berkas wordlist absen → nil (best-effort), bukan error/panik.
func TestAPIRoutePathsAbsent(t *testing.T) {
	t.Setenv("BUGHOUND_API_WORDLIST", filepath.Join(t.TempDir(), "tidak-ada.txt"))
	r := &Runner{APIRoutes: true}
	r.UseProxy("127.0.0.1:1")
	if got := r.apiRoutePaths(); got != nil {
		t.Errorf("berkas absen harus nil; dapat %v", got)
	}
}
