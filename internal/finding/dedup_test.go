package finding

import "testing"

// The four engine-specific open-redirect slugs on the same path (ZAP reports the
// redirect param, nuclei omits it) must collapse to a single dedup key, while
// redirects on a different path, and other types, stay separate.
func TestDedupOpenRedirectSynonymsCollapse(t *testing.T) {
	keys := map[string]bool{}
	for _, c := range []struct{ typ, url, method, param string }{
		{"off-site-redirect", "http://t/go?url=x", "GET", "url"},
		{"external-redirect", "http://t/go?url=y", "GET", "url"},
		{"open-redirect", "http://t/go?url=z", "", ""},
		{"open-redirect-bypass", "http://t/go?url=w", "GET", ""},
	} {
		keys[ComputeDedupKey(c.typ, "http://t", c.url, c.method, c.param)] = true
	}
	if len(keys) != 1 {
		t.Errorf("open-redirect synonyms on one path must share one dedup key; got %d distinct", len(keys))
	}

	// A redirect on a different path is a different finding.
	same := ComputeDedupKey("open-redirect", "http://t", "http://t/go?url=x", "GET", "url")
	other := ComputeDedupKey("open-redirect", "http://t", "http://t/out?url=x", "GET", "url")
	if same == other {
		t.Error("open redirects on different paths must NOT collapse")
	}

	// A non-redirect type keeps its parameter-level identity (no collateral).
	x1 := ComputeDedupKey("cross-site-scripting-reflected", "http://t", "http://t/p?q=1", "GET", "q")
	x2 := ComputeDedupKey("cross-site-scripting-reflected", "http://t", "http://t/p?r=1", "GET", "r")
	if x1 == x2 {
		t.Error("different params on a non-redirect type must stay separate")
	}
}
