package recon

import (
	"testing"

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

// UseAuthHeaders pada pipeline harus menyebar ke tahap aktif (httpx + katana).
func TestRealPipelineAuthHeadersFanout(t *testing.T) {
	hdr := "Cookie: session=abc"
	p := NewRealPipelineRate(0) // tahap httpx/katana terkonstruksi (non-nil)
	if hasHeaderArg(p.Httpx.args(), hdr) || hasHeaderArg(p.Katana.args(), hdr) {
		t.Error("tanpa UseAuthHeaders tak boleh ada -H")
	}
	p.UseAuthHeaders([]string{hdr})
	if !hasHeaderArg(p.Httpx.args(), hdr) {
		t.Error("httpx args harus memuat -H auth")
	}
	if !hasHeaderArg(p.Katana.args(), hdr) {
		t.Error("katana args harus memuat -H auth")
	}
}

// Crawl berlogin tak boleh mengikuti link logout (sesi mati); crawl tanpa login
// tak dibatasi.
func TestKatanaSkipsLogoutWhenAuth(t *testing.T) {
	cos := func(args []string) bool {
		for i := 0; i+1 < len(args); i++ {
			if args[i] == "-cos" && args[i+1] == engine.LogoutPattern {
				return true
			}
		}
		return false
	}
	k := &Katana{}
	if cos(k.args()) {
		t.Error("tanpa auth, katana tak boleh dibatasi -cos logout")
	}
	k.authHeaders = []string{"Cookie: s=1"}
	if !cos(k.args()) {
		t.Errorf("dengan auth, katana wajib -cos %q; dapat %v", engine.LogoutPattern, k.args())
	}
}
