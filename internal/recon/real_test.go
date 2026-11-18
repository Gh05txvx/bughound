package recon

import (
	"strings"
	"testing"
)

func TestSubfinderArgs(t *testing.T) {
	got := strings.Join(Subfinder{}.args("acme.io"), " ")
	for _, want := range []string{"-silent", "-d acme.io"} {
		if !strings.Contains(got, want) {
			t.Errorf("subfinder args must include %q; got: %s", want, got)
		}
	}
}

func TestHttpxProxyArg(t *testing.T) {
	h := &Httpx{}
	if strings.Contains(strings.Join(h.args(), " "), "proxy") {
		t.Error("without a proxy there must be no proxy flag")
	}
	h.proxyAddr = "127.0.0.1:9000"
	if !strings.Contains(strings.Join(h.args(), " "), "http://127.0.0.1:9000") {
		t.Error("httpx must use the proxy when it is set")
	}
}

func TestKatanaProxyArg(t *testing.T) {
	k := &Katana{proxyAddr: "127.0.0.1:9000"}
	if !strings.Contains(strings.Join(k.args(), " "), "http://127.0.0.1:9000") {
		t.Error("katana must use the proxy when it is set")
	}
}

// TestKatanaCrawlArgs pins a recon crawl deep enough for SPAs: -jc (JS crawl,
// endpoints in bundles) + an explicit depth. Without it recon is shallow → the
// recall of the whole roster (nuclei/ffuf/zap/dalfox) shrinks because the
// attack surface is small.
func TestKatanaCrawlArgs(t *testing.T) {
	got := strings.Join((&Katana{}).args(), " ")
	for _, want := range []string{"-silent", "-jc", "-d 3"} {
		if !strings.Contains(got, want) {
			t.Errorf("katana args must include %q (SPA/JS crawl); got: %s", want, got)
		}
	}
}

// UseProxy must point ONLY the active stages (httpx, katana) at the proxy, not subfinder.
func TestRealPipelineUseProxyActiveOnly(t *testing.T) {
	p := NewRealPipelineRate(0)
	p.UseProxy("127.0.0.1:9000")
	if p.Httpx.proxyAddr != "127.0.0.1:9000" || p.Katana.proxyAddr != "127.0.0.1:9000" {
		t.Error("httpx and katana must be pointed at the proxy")
	}
	// subfinder has no proxy (passive): its args never include a proxy.
	if strings.Contains(strings.Join(p.Subfinder.args("acme.io"), " "), "proxy") {
		t.Error("passive subfinder must not go through the proxy")
	}
}

// NewRealPipelineRate clamps the rate of the ACTIVE stages: -rate-limit on
// httpx and katana, -rate on naabu. NewRealPipelineRate(0) adds no rate flag.
func TestRealPipelineRate(t *testing.T) {
	if strings.Contains(strings.Join((&Httpx{}).args(), " "), "-rate-limit") {
		t.Error("without a rate, httpx must not have -rate-limit")
	}
	p := NewRealPipelineRate(12)
	if got := strings.Join(p.Httpx.args(), " "); !strings.Contains(got, "-rate-limit 12") {
		t.Errorf("httpx must have -rate-limit 12; got %q", got)
	}
	if got := strings.Join(p.Katana.args(), " "); !strings.Contains(got, "-rate-limit 12") {
		t.Errorf("katana must have -rate-limit 12; got %q", got)
	}
	if got := strings.Join(p.Naabu.args(), " "); !strings.Contains(got, "-rate 12") {
		t.Errorf("naabu must have -rate 12; got %q", got)
	}
}
