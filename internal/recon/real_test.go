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

// TestKatanaCrawlArgs mengunci crawl recon yang cukup dalam utk SPA: -jc (crawl JS,
// endpoint di bundel) + depth eksplisit. Tanpa ini recon dangkal → recall seluruh
// roster (nuclei/ffuf/zap/dalfox) mengecil karena permukaan serang sedikit.
func TestKatanaCrawlArgs(t *testing.T) {
	got := strings.Join((&Katana{}).args(), " ")
	for _, want := range []string{"-silent", "-jc", "-d 3"} {
		if !strings.Contains(got, want) {
			t.Errorf("katana args harus memuat %q (crawl SPA/JS); dapat: %s", want, got)
		}
	}
}

// UseProxy harus mengarahkan HANYA tahap aktif (httpx, katana), bukan subfinder.
func TestRealPipelineUseProxyActiveOnly(t *testing.T) {
	p := NewRealPipelineRate(0)
	p.UseProxy("127.0.0.1:9000")
	if p.Httpx.proxyAddr != "127.0.0.1:9000" || p.Katana.proxyAddr != "127.0.0.1:9000" {
		t.Error("httpx & katana harus diarahkan ke proxy")
	}
	// subfinder tak punya proxy (pasif) — args-nya tak pernah memuat proxy.
	if strings.Contains(strings.Join(p.Subfinder.args("acme.io"), " "), "proxy") {
		t.Error("subfinder pasif tidak boleh lewat proxy")
	}
}

// NewRealPipelineRate menjepit laju tahap AKTIF: -rate-limit pada httpx & katana,
// -rate pada naabu. NewRealPipelineRate(0) tidak menambah flag laju.
func TestRealPipelineRate(t *testing.T) {
	if strings.Contains(strings.Join((&Httpx{}).args(), " "), "-rate-limit") {
		t.Error("tanpa rate, httpx tak boleh punya -rate-limit")
	}
	p := NewRealPipelineRate(12)
	if got := strings.Join(p.Httpx.args(), " "); !strings.Contains(got, "-rate-limit 12") {
		t.Errorf("httpx harus -rate-limit 12; dapat %q", got)
	}
	if got := strings.Join(p.Katana.args(), " "); !strings.Contains(got, "-rate-limit 12") {
		t.Errorf("katana harus -rate-limit 12; dapat %q", got)
	}
	if got := strings.Join(p.Naabu.args(), " "); !strings.Contains(got, "-rate 12") {
		t.Errorf("naabu harus -rate 12; dapat %q", got)
	}
}
