package nuclei

import (
	"strings"
	"testing"
)

// Non-destructive must be in nucleiArgs whatever the profile: -no-interactsh and
// -exclude-tags dos. This is structural, not an option.
func TestSafetyNonDestructiveAlwaysOn(t *testing.T) {
	for _, st := range []bool{false, true} {
		r := &DASTRunner{RateLimit: 25, proxyAddr: "x:1", Safety: Safety{Stealth: st}}
		a := strings.Join(r.nucleiArgs("l"), " ")
		if !strings.Contains(a, "-no-interactsh") {
			t.Errorf("stealth=%v: -no-interactsh is required; got: %s", st, a)
		}
		if !strings.Contains(a, "-exclude-tags dos") {
			t.Errorf("stealth=%v: -exclude-tags dos is required; got: %s", st, a)
		}
	}
}

// Stealth adds low-and-slow: -c 1, a browser UA, the rate clamped to ≤
// stealthRateLimit, even when the requested RateLimit is far higher.
func TestSafetyStealthLowAndSlow(t *testing.T) {
	r := &DASTRunner{RateLimit: 50, proxyAddr: "x:1", Safety: Safety{Stealth: true}}
	a := strings.Join(r.nucleiArgs("l"), " ")
	for _, want := range []string{"-c 1", "-timeout 20", "User-Agent: Mozilla", "-rate-limit 3"} {
		if !strings.Contains(a, want) {
			t.Errorf("stealth nucleiArgs does not contain %q; got: %s", want, a)
		}
	}
	// A rate of 50 must be clamped to 3, NOT passed through as-is.
	if strings.Contains(a, "-rate-limit 50") {
		t.Errorf("stealth must not use a rate of 50; got: %s", a)
	}
	// Katana is low-and-slow too.
	k := strings.Join(r.katanaArgs("http://t/"), " ")
	for _, want := range []string{"-c 1", "User-Agent: Mozilla", "-rate-limit 3"} {
		if !strings.Contains(k, want) {
			t.Errorf("stealth katanaArgs does not contain %q; got: %s", want, k)
		}
	}
}

// Without stealth, the requested rate is honored and there are no stealth knobs.
func TestSafetyStandardRespectsRate(t *testing.T) {
	r := &DASTRunner{RateLimit: 25, proxyAddr: "x:1"} // Safety zero value = standard
	a := strings.Join(r.nucleiArgs("l"), " ")
	if !strings.Contains(a, "-rate-limit 25") {
		t.Errorf("standard mode must use -rate-limit 25; got: %s", a)
	}
	if strings.Contains(a, "-c 1") || strings.Contains(a, "User-Agent") {
		t.Errorf("standard mode must not inject stealth knobs; got: %s", a)
	}
}

// Destructive unsafe templates are rejected: the smuggling tag (desync) + 2 IDs
// that write to the target (webshell/F5). Required whatever the profile.
func TestSafetyExcludesDestructiveUnsafe(t *testing.T) {
	for _, st := range []bool{false, true} {
		r := &DASTRunner{RateLimit: 25, proxyAddr: "x:1", Safety: Safety{Stealth: st}}
		a := strings.Join(r.nucleiArgs("l"), " ")
		for _, want := range []string{"-exclude-tags dos,smuggling", "-exclude-id CVE-2021-30118,CVE-2023-46747"} {
			if !strings.Contains(a, want) {
				t.Errorf("stealth=%v: nucleiArgs does not contain %q; got: %s", st, want, a)
			}
		}
	}
}

// maxURLs is smaller in stealth (a narrowed scope).
func TestSafetyMaxURLs(t *testing.T) {
	if (Safety{Stealth: true}).maxURLs() >= (Safety{}).maxURLs() {
		t.Error("stealth must narrow the URL cap")
	}
	if (Safety{}).maxURLs() != maxDASTURLs {
		t.Errorf("standard mode maxURLs = %d, want %d", (Safety{}).maxURLs(), maxDASTURLs)
	}
}
