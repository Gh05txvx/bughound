package egress

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// Pengujian audit (BH-P03-APPSEC): proxy egress harus menghadang SSRF ke
// metadata/IP privat dan redirect ke luar scope, dengan target dummy lokal.

func TestAudit_ProxyBlocksMetadataSSRF(t *testing.T) {
	// Hanya host dummy in-scope; metadata cloud TIDAK.
	p := New(mustGuard(t, []string{"demo.test"}), nil)
	addr, stop, err := p.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	resp, err := proxyClient(t, addr).Get("http://169.254.169.254/latest/meta-data/")
	if err != nil {
		t.Fatalf("harus mendapat 403, bukan error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("SSRF metadata harus diblok proxy (403), dapat %d", resp.StatusCode)
	}
}

func TestAudit_ProxyBlocksRedirectToOutOfScope(t *testing.T) {
	// Backend in-scope yang me-redirect ke metadata (di luar scope).
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer backend.Close()
	bu, _ := url.Parse(backend.URL)

	p := New(mustGuard(t, []string{bu.Hostname()}), nil) // hanya backend in-scope
	addr, stop, _ := p.Listen("127.0.0.1:0")
	defer stop()

	// Klien mengikuti redirect; permintaan hasil redirect (ke metadata) harus
	// dihadang proxy sebelum koneksi dibuat.
	resp, err := proxyClient(t, addr).Get(backend.URL)
	if err != nil {
		t.Fatalf("permintaan gagal tak terduga: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("redirect ke luar scope harus berakhir 403 (diblok), dapat %d", resp.StatusCode)
	}
}
