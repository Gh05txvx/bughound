package egress

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"sync/atomic"
	"testing"

	"bughound/internal/scope"
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

// BH-F02: kebijakan IP — publik diizinkan, internal hanya bila eksplisit in-scope.
func TestAudit_IPAllowedPolicy(t *testing.T) {
	p := New(mustGuard(t, []string{"10.0.0.0/8"}), nil)
	cases := map[string]bool{
		"8.8.8.8":         true,  // publik
		"10.1.2.3":        true,  // eksplisit in-scope (CIDR)
		"169.254.169.254": false, // metadata
		"127.0.0.1":       false, // loopback
		"192.168.1.1":     false, // privat
		"::1":             false, // loopback IPv6
	}
	for ipStr, want := range cases {
		if got := p.ipAllowed(netip.MustParseAddr(ipStr)); got != want {
			t.Errorf("ipAllowed(%s)=%v, ingin %v", ipStr, got, want)
		}
	}
}

// BH-F02: hostname in-scope yang resolve ke IP internal (DNS rebinding) harus
// diblok saat dial, bukan lolos karena host cocok.
func TestAudit_ProxyBlocksDNSRebinding(t *testing.T) {
	p := New(mustGuard(t, []string{"rebind.test"}), nil) // host in-scope
	p.lookupIP = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil // resolve ke metadata
	}
	addr, stop, err := p.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	resp, err := proxyClient(t, addr).Get("http://rebind.test/")
	if err != nil {
		t.Fatalf("harus mendapat respons (bukan error klien): %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("SSRF via DNS rebinding (host in-scope -> IP metadata) harus diblok")
	}
}

// Eksklusi URL ber-host IP harus dihadang proxy; dulu entri itu tak pernah cocok
// sehingga request sampai ke backend.
func TestAudit_ProxyEnforcesIPURLExclusion(t *testing.T) {
	var hits atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer backend.Close()

	g, errs := scope.New([]string{"127.0.0.1"}, []string{"http://127.0.0.1/"})
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	addr, stop, err := New(g, nil).Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	resp, err := proxyClient(t, addr).Get(backend.URL + "/x")
	if err != nil {
		t.Fatalf("harus mendapat 403, bukan error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || hits.Load() != 0 {
		t.Errorf("status=%d hits=%d, ingin 403 tanpa menyentuh backend", resp.StatusCode, hits.Load())
	}
}

// Request HTTP tanpa port memakai port 80, jadi eksklusi port 80 berlaku. lookupIP
// dipasang agar kegagalan test pun tak pernah menyentuh jaringan.
func TestAudit_ProxyEnforcesDefaultPortExclusion(t *testing.T) {
	g, errs := scope.New([]string{"demo.test"}, []string{"demo.test:80"})
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	p := New(g, nil)
	p.lookupIP = func(ctx context.Context, host string) ([]netip.Addr, error) {
		t.Error("eksklusi harus menolak sebelum resolusi DNS")
		return nil, errors.New("jaringan diblok dalam test")
	}
	addr, stop, err := p.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	resp, err := proxyClient(t, addr).Get("http://demo.test/x")
	if err != nil {
		t.Fatalf("harus mendapat 403, bukan error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status=%d, ingin 403", resp.StatusCode)
	}
}
