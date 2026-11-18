package recon

import (
	"sort"
	"strings"
	"testing"
)

func TestGauArgs(t *testing.T) {
	got := strings.Join((&Gau{}).args(), " ")
	for _, w := range []string{"--threads", "--subs"} {
		if !strings.Contains(got, w) {
			t.Errorf("gau args are missing %q: %s", w, got)
		}
	}
}

func TestDnsxArgs(t *testing.T) {
	if !strings.Contains(strings.Join((&Dnsx{}).args(), " "), "-silent") {
		t.Error("dnsx args must have -silent")
	}
}

func TestNaabuArgs(t *testing.T) {
	got := strings.Join((&Naabu{}).args(), " ")
	for _, w := range []string{"-silent", "-scan-type c"} {
		if !strings.Contains(got, w) {
			t.Errorf("naabu args are missing %q: %s", w, got)
		}
	}
}

func TestHostsFromURLs(t *testing.T) {
	in := []string{
		"https://app.demo.test/login",
		"https://app.demo.test/x", // duplicate host
		"http://api.demo.test:8080/", // port stripped
		"plainhost",                  // no scheme
		"  ",                         // empty
	}
	got := hostsFromURLs(in)
	sort.Strings(got)
	want := []string{"api.demo.test", "app.demo.test", "plainhost"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("unique hosts = %v; want %v", got, want)
	}
}

// The new tools have no proxy (gau is passive, dnsx is DNS, naabu is raw TCP).
// NewRealPipelineRate includes them and UseProxy leaves them alone.
func TestNewRealPipelineIncludesNewTools(t *testing.T) {
	p := NewRealPipelineRate(0)
	if p.Gau == nil || p.Dnsx == nil || p.Naabu == nil {
		t.Fatal("NewRealPipelineRate must include Gau/Dnsx/Naabu")
	}
}
