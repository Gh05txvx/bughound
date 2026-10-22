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
	"io"
	"net"
	"net/http"
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

	mu     sync.Mutex
	denied []Decision
}

// New membuat Proxy terikat pada guard. audit boleh nil.
func New(guard *scope.Guard, audit func(Decision)) *Proxy {
	if audit == nil {
		audit = func(Decision) {}
	}
	return &Proxy{
		guard:     guard,
		audit:     audit,
		transport: &http.Transport{},
		dialer:    &net.Dialer{Timeout: 10 * time.Second},
	}
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
	dest, err := p.dialer.Dial("tcp", r.Host)
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

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return strings.TrimSpace(hostport)
}
