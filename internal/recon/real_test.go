package recon

import (
	"strings"
	"testing"
)

func TestSubfinderArgs(t *testing.T) {
	got := strings.Join(Subfinder{}.args("acme.io"), " ")
	for _, want := range []string{"-silent", "-d acme.io"} {
		if !strings.Contains(got, want) {
			t.Errorf("args subfinder harus memuat %q; dapat: %s", want, got)
		}
	}
}

func TestHttpxProxyArg(t *testing.T) {
	h := &Httpx{}
	if strings.Contains(strings.Join(h.args(), " "), "proxy") {
		t.Error("tanpa proxy tak boleh ada flag proxy")
	}
	h.proxyAddr = "127.0.0.1:9000"
	if !strings.Contains(strings.Join(h.args(), " "), "http://127.0.0.1:9000") {
		t.Error("httpx harus memakai proxy saat di-set")
	}
}

func TestKatanaProxyArg(t *testing.T) {
	k := &Katana{proxyAddr: "127.0.0.1:9000"}
	if !strings.Contains(strings.Join(k.args(), " "), "http://127.0.0.1:9000") {
		t.Error("katana harus memakai proxy saat di-set")
	}
}

// UseProxy harus mengarahkan HANYA tahap aktif (httpx, katana), bukan subfinder.
func TestRealPipelineUseProxyActiveOnly(t *testing.T) {
	p := NewRealPipeline()
	p.UseProxy("127.0.0.1:9000")
	if p.Httpx.proxyAddr != "127.0.0.1:9000" || p.Katana.proxyAddr != "127.0.0.1:9000" {
		t.Error("httpx & katana harus diarahkan ke proxy")
	}
	// subfinder tak punya proxy (pasif) — args-nya tak pernah memuat proxy.
	if strings.Contains(strings.Join(p.Subfinder.args("acme.io"), " "), "proxy") {
		t.Error("subfinder pasif tidak boleh lewat proxy")
	}
}
