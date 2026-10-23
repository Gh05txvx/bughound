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
			t.Errorf("gau args kurang %q: %s", w, got)
		}
	}
}

func TestDnsxArgs(t *testing.T) {
	if !strings.Contains(strings.Join((&Dnsx{}).args(), " "), "-silent") {
		t.Error("dnsx args harus -silent")
	}
}

func TestNaabuArgs(t *testing.T) {
	got := strings.Join((&Naabu{}).args(), " ")
	for _, w := range []string{"-silent", "-scan-type c"} {
		if !strings.Contains(got, w) {
			t.Errorf("naabu args kurang %q: %s", w, got)
		}
	}
}

func TestHostsFromURLs(t *testing.T) {
	in := []string{
		"https://app.demo.test/login",
		"https://app.demo.test/x", // duplikat host
		"http://api.demo.test:8080/", // port dilepas
		"plainhost",                  // tanpa skema
		"  ",                         // kosong
	}
	got := hostsFromURLs(in)
	sort.Strings(got)
	want := []string{"api.demo.test", "app.demo.test", "plainhost"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("host unik = %v; ingin %v", got, want)
	}
}

// Tool baru tidak punya proxy (gau pasif, dnsx DNS, naabu TCP mentah) — NewRealPipeline
// menyertakannya dan UseProxy tak menyentuhnya.
func TestNewRealPipelineIncludesNewTools(t *testing.T) {
	p := NewRealPipeline()
	if p.Gau == nil || p.Dnsx == nil || p.Naabu == nil {
		t.Fatal("NewRealPipeline harus menyertakan Gau/Dnsx/Naabu")
	}
}
