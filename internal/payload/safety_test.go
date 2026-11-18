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
		{[]string{"intrusive"}, SafetyMutating},  // intrusive marker
		{[]string{"exposure", "destructive"}, SafetyMutating},
	}
	for _, c := range cases {
		if got := classifySafety(c.tags); got != c.want {
			t.Errorf("classifySafety(%v) = %q, want %q", c.tags, got, c.want)
		}
	}
}

func TestSafetyValid(t *testing.T) {
	if !SafetyReadOnly.Valid() || !SafetyMutating.Valid() {
		t.Error("read-only and mutating must be valid")
	}
	if Safety("").Valid() || Safety("bogus").Valid() {
		t.Error("an empty or unknown value must be invalid")
	}
}

// A sidecar overrides the derived class (e.g. deliberately marking a detection
// template as mutating, or the other way round).
func TestSidecarOverridesSafety(t *testing.T) {
	e := Entry{Tags: []string{"dos"}} // derived = mutating
	applySidecar(&e, metaSidecar{Safety: "read-only"})
	if e.Safety != SafetyReadOnly {
		t.Errorf("the sidecar must override safety to read-only; got %q", e.Safety)
	}
	// An unknown sidecar value is ignored (it does not override).
	e2 := Entry{}
	applySidecar(&e2, metaSidecar{Safety: "bogus"})
	if e2.Safety != "" {
		t.Errorf("an unknown sidecar safety must be ignored; got %q", e2.Safety)
	}
}
