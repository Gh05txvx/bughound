// Package egress menegakkan scope guard pada koneksi keluar engine eksternal.
//
// Engine nyata (mis. nuclei) membuat request sendiri, sehingga pemeriksaan
// setelah hasil kembali terlambat. Proxy ini menjadi satu-satunya jalan keluar:
// engine dipaksa memakainya (mis. `nuclei -proxy http://127.0.0.1:<port>`), dan
// SETIAP request diperiksa ke scope guard SEBELUM koneksi diteruskan — inilah
// penegakan egress "sebelum koneksi" (BH-SPEC-SCOPE lapis 2) untuk engine luar.
//
// Untuk HTTPS (CONNECT), proxy hanya melihat host:port, jadi penegakan pada tunnel
// buta bersifat host-level. Host:port yang punya eksklusi ber-path dibuka agar tiap
// request dinilai (intercept.go). Egress non-HTTP tidak lewat sini dan memerlukan
// lapis OS (pertahanan berlapis).
package egress

import (
	"context"
	"crypto/tls"
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
	tunnel    *http.Transport // jalur keluar tunnel yang dibuka
	dialer    *net.Dialer
	finalDial dialFunc // nil = dial langsung; selain itu lewat proxy upstream
	lookupIP  func(ctx context.Context, host string) ([]netip.Addr, error)

	certOnce sync.Once
	cert     tls.Certificate
	certErr  error

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
	// Tunnel buta menyerahkan TLS ke engine, yang tak memverifikasi target karena
	// target uji sering bersertifikat tak valid. Jalur ini mengambil alih peran itu.
	// Keaslian tujuan tetap dijaga dialer ter-guard, bukan sertifikat. Kompresi tak
	// ditambahkan agar request dan respons sampai apa adanya.
	p.tunnel = &http.Transport{
		DialContext:        p.dialGuarded,
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10},
		DisableCompression: true,
		IdleConnTimeout:    30 * time.Second,
	}
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
	reason := scope.Reason("ip-internal")
	for _, ip := range ips {
		if p.ipAllowed(ip, port) {
			dest := net.JoinHostPort(ip.String(), port)
			if p.finalDial != nil {
				return p.finalDial(ctx, network, dest) // lewat upstream (ke IP yang sudah di-pin)
			}
			return p.dialer.DialContext(ctx, network, dest)
		}
		if !isSpecialIP(ip) {
			reason = scope.ReasonOutOfScope
		}
	}
	p.record(Decision{Method: "DIAL", Host: host, Target: host, Allowed: false, Reason: reason})
	return nil, fmt.Errorf("egress ditolak: %q menuju IP internal/terlarang (anti-SSRF / DNS rebinding)", host)
}

func (p *Proxy) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}
	return p.lookupIP(ctx, host)
}

// ipAllowed menilai IP hasil resolve untuk port tujuan. Host sudah lolos scope
// guard, jadi IP publik boleh kecuali dikecualikan; IP internal/khusus wajib
// eksplisit in-scope. Port ikut dinilai agar eksklusi satu port tak menutup port
// lain di IP yang sama.
func (p *Proxy) ipAllowed(ip netip.Addr, port string) bool {
	ip = ip.Unmap() // bentuk ::ffff:a.b.c.d tak cocok entri IPv4-nya
	d := p.guard.Evaluate(net.JoinHostPort(ip.String(), port))
	if isSpecialIP(ip) {
		return d.Allowed
	}
	return d.Allowed || d.Reason == scope.ReasonNotInScope
}

func isSpecialIP(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() ||
		a.IsMulticast() || a.IsUnspecified()
}

// SetUpstream mengarahkan koneksi akhir (ke IP yang sudah di-scope-check &
// di-pin) lewat satu atau beberapa proxy (RANTAI, urut hop pertama→terakhir).
// Skema tiap hop: http/https (CONNECT), socks5/socks5h. Tanpa URL (atau semua
// kosong) kembali ke dial langsung. Scope guard & IP-pinning TETAP di hulu —
// rantai hanya mengganti jalur, bukan memintas keamanan.
func (p *Proxy) SetUpstream(proxyURLs ...string) error {
	var chain []string
	for _, u := range proxyURLs {
		if strings.TrimSpace(u) != "" {
			chain = append(chain, u)
		}
	}
	if len(chain) == 0 {
		p.finalDial = nil
		return nil
	}
	d, err := buildChainDialer(chain, p.dialer)
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
	p.forward(w, r, p.transport)
}

// forward adalah gerbang per-request: HTTP biasa dan tunnel yang dibuka sama-sama
// lewat sini, sehingga hanya ada satu aturan penegakan.
func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, rt http.RoundTripper) {
	d := p.guard.Evaluate(r.URL.String())
	p.record(Decision{Method: r.Method, Host: r.URL.Hostname(), Target: d.Target, Allowed: d.Allowed, Reason: d.Reason})
	if !d.Allowed {
		http.Error(w, "egress ditolak scope guard: "+string(d.Reason), http.StatusForbidden)
		return
	}

	r.RequestURI = "" // wajib kosong untuk RoundTrip
	resp, err := rt.RoundTrip(r)
	if err != nil {
		http.Error(w, "egress gagal: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	// Sesudah 101 yang lewat bukan HTTP lagi, jadi tak ada request yang bisa dinilai.
	if resp.StatusCode == http.StatusSwitchingProtocols {
		http.Error(w, "egress ditolak: upgrade protokol tak didukung", http.StatusBadGateway)
		return
	}
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
	if p.guard.PathScoped(r.Host) {
		client, rw, err := hj.Hijack()
		if err != nil {
			return
		}
		_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		p.serveOpened(client, rw.Reader, r.Host)
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
