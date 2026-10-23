// Package egress menegakkan scope guard pada koneksi keluar engine eksternal.
//
// Engine nyata (mis. nuclei) membuat request sendiri, sehingga pemeriksaan
// setelah hasil kembali terlambat. Proxy ini menjadi satu-satunya jalan keluar:
// engine dipaksa memakainya (mis. `nuclei -proxy http://127.0.0.1:<port>`), dan
// SETIAP request diperiksa ke scope guard SEBELUM koneksi diteruskan — inilah
// penegakan egress "sebelum koneksi" (BH-SPEC-SCOPE lapis 2) untuk engine luar.
//
// Catatan: untuk HTTPS (CONNECT), proxy hanya melihat host:port (tanpa MITM),
// jadi penegakan pada tunnel bersifat host-level. Egress non-HTTP tidak lewat
// sini dan memerlukan lapis OS (pertahanan berlapis).
package egress

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"bughound/internal/scope"
)

// Decision mencatat keputusan proxy untuk satu request (untuk audit).
type Decision struct {
	Method  string
	Host    string
	Target  string // target ternormalkan dari scope guard
	Allowed bool
	Reason  scope.Reason
}

// Proxy adalah proxy HTTP(S) yang menegakkan scope guard.
type Proxy struct {
	guard     *scope.Guard
	audit     func(Decision)
	transport http.RoundTripper
	dialer    *net.Dialer
	finalDial dialFunc // nil = dial langsung; selain itu lewat proxy upstream
	lookupIP  func(ctx context.Context, host string) ([]netip.Addr, error)

	mu     sync.Mutex
	denied []Decision
}

// New membuat Proxy terikat pada guard. audit boleh nil.
func New(guard *scope.Guard, audit func(Decision)) *Proxy {
	if audit == nil {
		audit = func(Decision) {}
	}
	p := &Proxy{
		guard:  guard,
		audit:  audit,
		dialer: &net.Dialer{Timeout: 10 * time.Second},
		lookupIP: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		},
	}
	// Semua dial (HTTP forward & CONNECT) lewat dialer ter-guard: anti SSRF ke
	// IP internal + anti DNS rebinding (IP yang dicek = IP yang disambung).
	p.transport = &http.Transport{DialContext: p.dialGuarded}
	return p
}

// dialGuarded me-resolve host, menolak IP internal/terlarang (kecuali eksplisit
// in-scope), lalu menyambung ke IP yang SUDAH diperiksa (di-pin) agar resolusi
// tak bisa berubah antara pengecekan dan koneksi (DNS rebinding).
func (p *Proxy) dialGuarded(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := p.resolve(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("egress: resolusi %q gagal: %w", host, err)
	}
	for _, ip := range ips {
		if p.ipAllowed(ip) {
			dest := net.JoinHostPort(ip.String(), port)
			if p.finalDial != nil {
				return p.finalDial(ctx, network, dest) // lewat upstream (ke IP yang sudah di-pin)
			}
			return p.dialer.DialContext(ctx, network, dest)
		}
	}
	p.record(Decision{Method: "DIAL", Host: host, Target: host, Allowed: false, Reason: scope.Reason("ip-internal")})
	return nil, fmt.Errorf("egress ditolak: %q menuju IP internal/terlarang (anti-SSRF / DNS rebinding)", host)
}

func (p *Proxy) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}
	return p.lookupIP(ctx, host)
}

// ipAllowed: IP publik biasa diizinkan (host sudah lolos scope guard); IP
// internal/khusus hanya bila eksplisit in-scope sebagai IP/CIDR.
func (p *Proxy) ipAllowed(ip netip.Addr) bool {
	if !isSpecialIP(ip) {
		return true
	}
	return p.guard.Evaluate(ip.String()).Allowed
}

func isSpecialIP(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() ||
		a.IsMulticast() || a.IsUnspecified()
}

// SetUpstream mengarahkan koneksi akhir (ke IP yang sudah di-scope-check &
// di-pin) lewat proxy upstream. Skema: http/https (CONNECT), socks5/socks5h.
// URL kosong mengembalikan ke dial langsung. Scope guard & IP-pinning TETAP di
// hulu — upstream hanya mengganti jalur, bukan memintas keamanan.
func (p *Proxy) SetUpstream(proxyURL string) error {
	if strings.TrimSpace(proxyURL) == "" {
		p.finalDial = nil
		return nil
	}
	d, err := upstreamDialer(proxyURL, p.dialer)
	if err != nil {
		return err
	}
	p.finalDial = d
	return nil
}

// Listen menjalankan proxy pada addr (pakai "127.0.0.1:0" untuk port acak) dan
// mengembalikan alamat terikat beserta fungsi stop.
func (p *Proxy) Listen(addr string) (string, func() error, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", nil, err
	}
	srv := &http.Server{Handler: p}
	go srv.Serve(ln)
	return ln.Addr().String(), srv.Close, nil
}

// Denials mengembalikan salinan daftar penolakan yang tercatat sejauh ini.
func (p *Proxy) Denials() []Decision {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]Decision, len(p.denied))
	copy(out, p.denied)
	return out
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handleHTTP(w, r)
}

func (p *Proxy) record(d Decision) {
	p.audit(d)
	if !d.Allowed {
		p.mu.Lock()
		p.denied = append(p.denied, d)
		p.mu.Unlock()
	}
}

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Request proxy HTTP biasa memakai URL absolut (http://host/path).
	d := p.guard.Evaluate(r.URL.String())
	p.record(Decision{Method: r.Method, Host: r.URL.Hostname(), Target: d.Target, Allowed: d.Allowed, Reason: d.Reason})
	if !d.Allowed {
		http.Error(w, "egress ditolak scope guard: "+string(d.Reason), http.StatusForbidden)
		return
	}

	r.RequestURI = "" // wajib kosong untuk RoundTrip
	resp, err := p.transport.RoundTrip(r)
	if err != nil {
		http.Error(w, "egress gagal: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	// r.Host berbentuk host:port. Scope guard dievaluasi atas host tujuan.
	d := p.guard.Evaluate(r.Host)
	p.record(Decision{Method: "CONNECT", Host: hostOnly(r.Host), Target: d.Target, Allowed: d.Allowed, Reason: d.Reason})
	if !d.Allowed {
		http.Error(w, "egress ditolak scope guard: "+string(d.Reason), http.StatusForbidden)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "proxy: hijack tak didukung", http.StatusInternalServerError)
		return
	}
	dest, err := p.dialGuarded(r.Context(), "tcp", r.Host)
	if err != nil {
		http.Error(w, "egress gagal: "+err.Error(), http.StatusBadGateway)
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		dest.Close()
		return
	}
	_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	go pipe(dest, client)
	go pipe(client, dest)
}

func pipe(dst, src net.Conn) {
	defer dst.Close()
	defer src.Close()
	_, _ = io.Copy(dst, src)
}

func copyHeader(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

// ProxyEnv mengembalikan environment (berbasis base, mis. os.Environ()) yang
// MEMAKSA HTTP(S)_PROXY/ALL_PROXY ke proxyURL dan mengosongkan NO_PROXY.
// Dipakai sebagai pertahanan berlapis (belt-and-suspenders) agar subprocess
// engine tetap ber-egress lewat proxy scope guard walau mengabaikan flag
// -proxy. (Egress non-HTTP tetap di luar jangkauan proxy — lihat ADR egress.)
func ProxyEnv(base []string, proxyURL string) []string {
	out := make([]string, 0, len(base)+8)
	for _, kv := range base {
		up := strings.ToUpper(kv)
		switch {
		case strings.HasPrefix(up, "HTTP_PROXY="),
			strings.HasPrefix(up, "HTTPS_PROXY="),
			strings.HasPrefix(up, "ALL_PROXY="),
			strings.HasPrefix(up, "NO_PROXY="):
			// buang; akan diganti paksa di bawah
		default:
			out = append(out, kv)
		}
	}
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		out = append(out, k+"="+proxyURL)
	}
	return append(out, "NO_PROXY=", "no_proxy=")
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return strings.TrimSpace(hostport)
}
