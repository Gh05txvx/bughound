package egress

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
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
		if got := p.ipAllowed(netip.MustParseAddr(ipStr), "80"); got != want {
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

// Nama in-scope bisa menunjuk IP publik yang dikecualikan. Tak ada koneksi nyata di
// sini: finalDial hanya mencatat tujuan, jadi IP ini tak pernah dihubungi.
func TestAudit_DialNeverReachesExcludedPublicIP(t *testing.T) {
	cases := []struct {
		name string
		out  []string
		ips  []string
		port string
		want string // tujuan dial; kosong berarti ditolak
	}{
		{"IP dikecualikan", []string{"203.0.113.10"}, []string{"203.0.113.10"}, "443", ""},
		{"CIDR dikecualikan", []string{"203.0.113.0/24"}, []string{"203.0.113.77"}, "443", ""},
		{"IP ter-map ke IPv6", []string{"203.0.113.10"}, []string{"::ffff:203.0.113.10"}, "443", ""},
		{"port yang dikecualikan", []string{"203.0.113.10:8443"}, []string{"203.0.113.10"}, "8443", ""},
		{"port lain tetap boleh", []string{"203.0.113.10:8443"}, []string{"203.0.113.10"}, "443", "203.0.113.10:443"},
		{"eksklusi ber-path tak menutup IP", []string{"https://203.0.113.10/admin"}, []string{"203.0.113.10"}, "443", "203.0.113.10:443"},
		{"IP lain dari nama yang sama dipakai", []string{"203.0.113.10"}, []string{"203.0.113.10", "203.0.113.11"}, "443", "203.0.113.11:443"},
		{"IP lain yang tak dikecualikan", []string{"203.0.113.99"}, []string{"203.0.113.10"}, "443", "203.0.113.10:443"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := New(guardWith(t, []string{"demo.test"}, tc.out), nil)
			p.lookupIP = func(context.Context, string) ([]netip.Addr, error) {
				var ips []netip.Addr
				for _, s := range tc.ips {
					ips = append(ips, netip.MustParseAddr(s))
				}
				return ips, nil
			}
			var got string
			p.finalDial = func(_ context.Context, _, addr string) (net.Conn, error) {
				got = addr
				return nil, errors.New("stub: tak ada koneksi nyata")
			}
			_, err := p.dialGuarded(context.Background(), "tcp", "demo.test:"+tc.port)
			if got != tc.want {
				t.Fatalf("tujuan dial = %q, ingin %q", got, tc.want)
			}
			if tc.want != "" {
				return
			}
			if err == nil || !strings.Contains(err.Error(), "egress ditolak") {
				t.Errorf("harus ditolak, dapat: %v", err)
			}
			d := p.Denials()
			if len(d) != 1 || d[0].Reason != scope.ReasonOutOfScope {
				t.Errorf("penolakan = %+v, ingin satu out-of-scope", d)
			}
		})
	}
}

// Dari sisi klien: nama lolos guard saat request, lalu ditahan saat dial.
func TestAudit_ProxyBlocksNameResolvingToExcludedIP(t *testing.T) {
	p := New(guardWith(t, []string{"demo.test"}, []string{"203.0.113.10"}), nil)
	p.lookupIP = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nil
	}
	var dials atomic.Int32
	p.finalDial = func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("stub: tak ada koneksi nyata")
	}
	resp, err := proxyClient(t, startProxy(t, p)).Get("http://demo.test/")
	if err != nil {
		t.Fatalf("harus mendapat respons: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, ingin 502", resp.StatusCode)
	}
	if n := dials.Load(); n != 0 {
		t.Errorf("%d dial sampai ke IP yang dikecualikan", n)
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

// Port ikut dinilai saat dial: eksklusi berport hanya menutup port itu, dan entri
// in-scope berport cukup sebagai izin eksplisit IP internal.
func TestAudit_IPAllowedHonoursPort(t *testing.T) {
	p := New(guardWith(t, []string{"10.0.0.0/8", "192.168.1.5:8080", "http://172.16.0.9:3000/"}, []string{"10.0.0.5:8080", "http://10.0.0.6/admin"}), nil)
	cases := []struct {
		ip, port string
		want     bool
	}{
		{"10.0.0.5", "8080", false}, // port yang dikecualikan
		{"10.0.0.5", "80", true},    // port lain IP yang sama
		{"10.0.0.7", "8080", true},  // IP lain
		{"10.0.0.6", "80", true},    // eksklusi ber-path dinilai per request
		{"192.168.1.5", "8080", true},
		{"192.168.1.5", "80", false}, // izin hanya untuk port itu
		{"172.16.0.9", "3000", true},
		{"172.16.0.9", "80", false},
		{"8.8.8.8", "8080", true},    // IP publik yang tak dikecualikan
		{"10.0.0.8", "bukan", false}, // port tak valid: fail closed
		{"8.8.8.8", "bukan", false},  // berlaku juga untuk IP publik
	}
	for _, c := range cases {
		if got := p.ipAllowed(netip.MustParseAddr(c.ip), c.port); got != c.want {
			t.Errorf("ipAllowed(%s, %s) = %v, ingin %v", c.ip, c.port, got, c.want)
		}
	}
}

// Skenario lab S7a: eksklusi satu port dulu memblokir semua port IP itu saat dial.
func TestAudit_PortExclusionBlocksOnlyThatPort(t *testing.T) {
	var openHits, closedHits atomic.Int32
	open := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { openHits.Add(1) }))
	defer open.Close()
	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { closedHits.Add(1) }))
	defer closed.Close()

	g := guardWith(t, []string{"127.0.0.1"}, []string{strings.TrimPrefix(closed.URL, "http://")})
	c := proxyClient(t, startProxy(t, New(g, nil)))
	if st := statusOf(t, c, open.URL+"/x"); st != http.StatusOK {
		t.Errorf("port lain = %d, ingin 200", st)
	}
	if st := statusOf(t, c, closed.URL+"/x"); st != http.StatusForbidden {
		t.Errorf("port terlarang = %d, ingin 403", st)
	}
	if openHits.Load() != 1 || closedHits.Load() != 0 {
		t.Errorf("hits open=%d closed=%d, ingin 1 dan 0", openHits.Load(), closedHits.Load())
	}
}

// Skenario lab S9: in-scope URL ber-IP privat dan berport dulu lolos input lalu
// semua koneksinya ditolak dial.
func TestAudit_InScopePortEntryReachesPrivateIP(t *testing.T) {
	var hits atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer backend.Close()

	c := proxyClient(t, startProxy(t, New(guardWith(t, []string{backend.URL + "/"}, nil), nil)))
	if st := statusOf(t, c, backend.URL+"/x"); st != http.StatusOK {
		t.Errorf("status = %d, ingin 200", st)
	}
	if hits.Load() != 1 {
		t.Errorf("hits = %d, ingin 1", hits.Load())
	}
}

// Skenario lab S10: entri ber-path bukan izin atas IP internalnya. Sengaja tetap
// ditolak, karena dial tak mengenal path.
func TestAudit_PathEntryIsNotAPermitForPrivateIP(t *testing.T) {
	var hits atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer backend.Close()

	c := proxyClient(t, startProxy(t, New(guardWith(t, []string{backend.URL + "/public"}, nil), nil)))
	if st := statusOf(t, c, backend.URL+"/public/x"); st != http.StatusBadGateway {
		t.Errorf("status = %d, ingin 502", st)
	}
	if hits.Load() != 0 {
		t.Errorf("hits = %d, ingin 0", hits.Load())
	}
}
