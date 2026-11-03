package payload

import "testing"

func TestClassifySafety(t *testing.T) {
	cases := []struct {
		tags []string
		want Safety
	}{
		{[]string{"sqli", "fuzz"}, SafetyReadOnly},
		{[]string{"ssrf", "cve"}, SafetyReadOnly},
		{nil, SafetyReadOnly},
		{[]string{"dos"}, SafetyMutating},
		{[]string{"cve", "DOS"}, SafetyMutating}, // case-insensitive
		{[]string{"intrusive"}, SafetyMutating},  // penanda intrusive
		{[]string{"exposure", "destructive"}, SafetyMutating},
	}
	for _, c := range cases {
		if got := classifySafety(c.tags); got != c.want {
			t.Errorf("classifySafety(%v) = %q, mau %q", c.tags, got, c.want)
		}
	}
}

func TestSafetyValid(t *testing.T) {
	if !SafetyReadOnly.Valid() || !SafetyMutating.Valid() {
		t.Error("read-only & mutating harus valid")
	}
	if Safety("").Valid() || Safety("bogus").Valid() {
		t.Error("nilai kosong/asing harus tidak valid")
	}
}

// Sidecar menimpa klasifikasi turunan (mis. menandai template deteksi sebagai
// mutating secara sadar, atau sebaliknya).
func TestSidecarOverridesSafety(t *testing.T) {
	e := Entry{Tags: []string{"dos"}} // turunan = mutating
	applySidecar(&e, metaSidecar{Safety: "read-only"})
	if e.Safety != SafetyReadOnly {
		t.Errorf("sidecar harus menimpa safety ke read-only; dapat %q", e.Safety)
	}
	// Sidecar nilai asing diabaikan (tak menimpa).
	e2 := Entry{}
	applySidecar(&e2, metaSidecar{Safety: "bogus"})
	if e2.Safety != "" {
		t.Errorf("safety sidecar asing harus diabaikan; dapat %q", e2.Safety)
	}
}
