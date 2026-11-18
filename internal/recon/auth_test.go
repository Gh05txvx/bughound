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

// UseAuthHeaders on the pipeline must fan out to the active stages (httpx + katana).
func TestRealPipelineAuthHeadersFanout(t *testing.T) {
	hdr := "Cookie: session=abc"
	p := NewRealPipelineRate(0) // the httpx/katana stages are constructed (non-nil)
	if hasHeaderArg(p.Httpx.args(), hdr) || hasHeaderArg(p.Katana.args(), hdr) {
		t.Error("without UseAuthHeaders there must be no -H")
	}
	p.UseAuthHeaders([]string{hdr})
	if !hasHeaderArg(p.Httpx.args(), hdr) {
		t.Error("httpx args must include the auth -H")
	}
	if !hasHeaderArg(p.Katana.args(), hdr) {
		t.Error("katana args must include the auth -H")
	}
}

// A logged-in crawl must not follow logout links (the session dies); a crawl
// without login is not restricted.
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
		t.Error("without auth, katana must not be restricted by the logout -cos")
	}
	k.authHeaders = []string{"Cookie: s=1"}
	if !cos(k.args()) {
		t.Errorf("with auth, katana must have -cos %q; got %v", engine.LogoutPattern, k.args())
	}
}
