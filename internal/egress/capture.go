package egress

// Capture gateway: reverse proxy yang menegakkan scope guard ke SATU target
// in-scope sambil merekam tiap request sebagai kandidat target scan.
//
// Berbeda dari Proxy (forward proxy untuk engine), gateway ini dipakai manusia:
// hunter mengarahkan browser ke listener lokal gateway dan browsing target
// seperti biasa; gateway meneruskan transparan ke target asli (reverse proxy)
// lewat transport ter-guard milik Proxy (resolve → tolak IP internal → pin IP,
// plus rantai upstream bila diset). Karena memakai ulang transport itu, gateway
// TAK PERNAH menjangkau host di luar scope — bahkan saat browsing manual. Tiap
// request yang lewat direkam (dedup) agar bisa "di-promote" jadi scan.
//
// Listener lokal berbicara HTTP biasa (loopback tepercaya); re-originasi ke
// target HTTPS ditangani transport (SNI = host target, IP di-pin) sehingga tak
// perlu memasang CA cert di browser — cocok untuk alur lewat UI web.

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Waiter membatasi laju egress (dipenuhi *ratelimit.Limiter). Gateway menunggu
// token sebelum tiap penerusan — rate limiter tetap di jalur eksekusi.
type Waiter interface {
	Wait(ctx context.Context) error
}

// CaptureRecord adalah satu request teramati lewat gateway (kandidat scan).
type CaptureRecord struct {
	Method string
	URL    string // absolut: scheme://host/path?query (di target in-scope)
	Status int    // status terakhir yang teramati (0 bila gagal/ belum)
	Count  int    // berapa kali diamati (dedup per method+URL)
	First  time.Time
	Last   time.Time
}

// Gateway adalah reverse proxy yang menegakkan scope guard ke satu target
// in-scope dan merekam tiap request.
type Gateway struct {
	p      *Proxy
	target *url.URL
	lim    Waiter
	now    func() time.Time

	rp *httputil.ReverseProxy

	mu      sync.Mutex
	records map[string]*CaptureRecord
	order   []string
}

// NewGateway membuat gateway ke target (mis. "https://app.demo.test" atau
// "app.demo.test"; tanpa skema dianggap https). Target WAJIB lolos scope guard
// milik p (default-deny) — di luar scope mengembalikan error (fail closed).
// lim boleh nil (tanpa pembatasan laju), tetapi jalur web selalu mengisinya.
func NewGateway(p *Proxy, target string, lim Waiter) (*Gateway, error) {
	t := strings.TrimSpace(target)
	if t == "" {
		return nil, fmt.Errorf("capture: target kosong")
	}
	if !strings.Contains(t, "://") {
		t = "https://" + t
	}
	u, err := url.Parse(t)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("capture: target tak valid: %q", target)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("capture: skema target harus http/https, bukan %q", u.Scheme)
	}
	// Scope guard: target harus in-scope. Inilah gate yang sama dengan egress.
	if d := p.guard.Evaluate(u.String()); !d.Allowed {
		p.record(Decision{Method: "CAPTURE", Host: u.Hostname(), Target: d.Target, Allowed: false, Reason: d.Reason})
		return nil, fmt.Errorf("capture: target di luar scope (ditolak): %s", d.Reason)
	}
	g := &Gateway{
		p: p, target: u, lim: lim, now: time.Now,
		records: map[string]*CaptureRecord{},
	}
	base := &url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}
	g.rp = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(base) // arahkan ke target in-scope; Host ikut jadi host target.
			// Sengaja TIDAK memanggil pr.SetXForwarded(): jangan bocorkan IP klien lokal.
		},
		Transport: captureRT{g},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			http.Error(w, "capture egress gagal: "+err.Error(), http.StatusBadGateway)
		},
	}
	return g, nil
}

// captureRT membungkus transport ter-guard: scope re-check (lapis egress) +
// rate limit + rekam, lalu teruskan.
type captureRT struct{ g *Gateway }

func (c captureRT) RoundTrip(req *http.Request) (*http.Response, error) {
	g := c.g
	// Lapis egress: evaluasi ulang URL keluar absolut sebelum menyambung.
	d := g.p.guard.Evaluate(req.URL.String())
	g.p.record(Decision{Method: req.Method, Host: req.URL.Hostname(), Target: d.Target, Allowed: d.Allowed, Reason: d.Reason})
	if !d.Allowed {
		return nil, fmt.Errorf("capture: di luar scope: %s", d.Reason)
	}
	// Rate limiter di jalur eksekusi.
	if g.lim != nil {
		if err := g.lim.Wait(req.Context()); err != nil {
			return nil, err
		}
	}
	resp, err := g.p.transport.RoundTrip(req)
	status := 0
	if resp != nil {
		status = resp.StatusCode
	}
	g.observe(req.Method, req.URL, status)
	return resp, err
}

func (g *Gateway) observe(method string, u *url.URL, status int) {
	key := method + " " + canonURL(u)
	g.mu.Lock()
	defer g.mu.Unlock()
	rec, ok := g.records[key]
	now := g.now()
	if !ok {
		rec = &CaptureRecord{Method: method, URL: canonURL(u), First: now}
		g.records[key] = rec
		g.order = append(g.order, key)
	}
	rec.Count++
	rec.Last = now
	if status != 0 {
		rec.Status = status
	}
}

func canonURL(u *url.URL) string {
	c := &url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path, RawQuery: u.RawQuery}
	return c.String()
}

// ServeHTTP menjalankan reverse proxy ter-guard.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) { g.rp.ServeHTTP(w, r) }

// Target mengembalikan target in-scope yang dilayani gateway.
func (g *Gateway) Target() string { return g.target.String() }

// Records mengembalikan salinan kandidat teramati, urut kemunculan pertama.
func (g *Gateway) Records() []CaptureRecord {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]CaptureRecord, 0, len(g.order))
	for _, k := range g.order {
		out = append(out, *g.records[k])
	}
	return out
}

// Listen menjalankan gateway pada addr (pakai "127.0.0.1:0" untuk port acak) dan
// mengembalikan alamat terikat beserta fungsi stop.
func (g *Gateway) Listen(addr string) (string, func() error, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", nil, err
	}
	srv := &http.Server{Handler: g}
	go srv.Serve(ln)
	return ln.Addr().String(), srv.Close, nil
}
