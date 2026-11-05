package egress

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"bughound/internal/scope"
)

// seenRequests mencatat apa yang benar-benar sampai ke backend.
type seenRequests struct {
	mu    sync.Mutex
	uris  []string
	hosts []string
}

func (s *seenRequests) add(r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.uris = append(s.uris, r.RequestURI)
	s.hosts = append(s.hosts, r.Host)
}

func (s *seenRequests) list() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.uris...)
}

func (s *seenRequests) under(prefix string) []string {
	var out []string
	for _, u := range s.list() {
		p, _, _ := strings.Cut(u, "?")
		if p == prefix || strings.HasPrefix(p, prefix+"/") {
			out = append(out, u)
		}
	}
	return out
}

func guardWith(t *testing.T, in, out []string) *scope.Guard {
	t.Helper()
	g, errs := scope.New(in, out)
	if len(errs) > 0 {
		t.Fatalf("scope.New: %v", errs)
	}
	return g
}

func startProxy(t *testing.T, p *Proxy) string {
	t.Helper()
	addr, stop, err := p.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stop() })
	return addr
}

func tlsTarget(t *testing.T) (*httptest.Server, *seenRequests, string) {
	t.Helper()
	got := &seenRequests{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.add(r)
		fmt.Fprint(w, "ok")
	}))
	t.Cleanup(srv.Close)
	return srv, got, strings.TrimPrefix(srv.URL, "https://")
}

// insecureClient meniru engine: lewat proxy, tak memverifikasi sertifikat.
// Balasan 200 CONNECT wajib membawa header (Proxy-Agent), bukan status-line
// telanjang: klien rawhttp nuclei mem-Peek 5 byte sesudah status-line dan menggantung
// bila hanya ada CRLF, membuat template unsafe mati tiap scan. Diuji di jalur tunnel
// buta (tulis balasan sesudah dial) dan jalur dibuka (tulis balasan lalu serveOpened).
func TestIntercept_ConnectReplyCarriesHeader(t *testing.T) {
	_, _, host := tlsTarget(t)
	cases := []struct {
		name string
		out  []string
	}{
		{"tunnel buta", nil},
		{"dibuka", []string{"https://" + host + "/admin"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr := startProxy(t, New(guardWith(t, []string{"127.0.0.1"}, tc.out), nil))
			conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", host, host)
			resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
			if err != nil {
				t.Fatalf("baca respons CONNECT: %v", err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, ingin 200", resp.StatusCode)
			}
			if resp.Header.Get("Proxy-Agent") == "" {
				t.Errorf("balasan CONNECT tanpa header Proxy-Agent (klien rawhttp bisa menggantung di Peek)")
			}
		})
	}
}

func insecureClient(t *testing.T, addr string) *http.Client {
	t.Helper()
	pu, _ := url.Parse("http://" + addr)
	return &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			Proxy:              http.ProxyURL(pu),
			TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
			DisableCompression: true,
		},
	}
}

func openTunnel(t *testing.T, proxyAddr, authority string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority)
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("baca respons CONNECT: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT %s = %d, ingin 200", authority, resp.StatusCode)
	}
	return conn
}

func tlsTunnel(t *testing.T, proxyAddr, authority string) *tls.Conn {
	t.Helper()
	tc := tls.Client(openTunnel(t, proxyAddr, authority), &tls.Config{InsecureSkipVerify: true})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	return tc
}

func readStatus(t *testing.T, br *bufio.Reader) int {
	t.Helper()
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("baca respons: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func statusOf(t *testing.T, c *http.Client, rawURL string) int {
	t.Helper()
	resp, err := c.Get(rawURL)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// Inti perbaikan: eksklusi ber-path berlaku di HTTPS. Lab mengukur 235 request
// sampai ke path terlarang sebelum ini, 142 di antaranya membawa payload.
func TestIntercept_BlocksExcludedPathOverHTTPS(t *testing.T) {
	srv, got, host := tlsTarget(t)
	addr := startProxy(t, New(guardWith(t, []string{"127.0.0.1"}, []string{"https://" + host + "/admin"}), nil))
	c := insecureClient(t, addr)

	for _, p := range []string{"/admin", "/admin/", "/admin/users.html?id=1'", "/%61dmin", "/public/../admin"} {
		if st := statusOf(t, c, srv.URL+p); st != http.StatusForbidden {
			t.Errorf("GET %s = %d, ingin 403", p, st)
		}
	}
	for _, p := range []string{"/", "/public/", "/administrator", "/public?next=/admin"} {
		if st := statusOf(t, c, srv.URL+p); st != http.StatusOK {
			t.Errorf("GET %s = %d, ingin 200", p, st)
		}
	}
	if hit := got.under("/admin"); len(hit) != 0 {
		t.Errorf("path terlarang tersentuh: %v", hit)
	}
	if n := len(got.list()); n != 4 {
		t.Errorf("backend kena %d kali, ingin 4 (%v)", n, got.list())
	}
}

// Bentuk host bernama: keluaran importer untuk program nyata.
func TestIntercept_BlocksExcludedPathOnNamedHost(t *testing.T) {
	_, got, host := tlsTarget(t)
	_, port, _ := net.SplitHostPort(host)
	p := New(guardWith(t, []string{"demo.test", "127.0.0.1"}, []string{"demo.test/admin"}), nil)
	p.lookupIP = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	c := insecureClient(t, startProxy(t, p))
	base := "https://demo.test:" + port

	if st := statusOf(t, c, base+"/admin/x"); st != http.StatusForbidden {
		t.Errorf("/admin/x = %d, ingin 403", st)
	}
	if st := statusOf(t, c, base+"/public"); st != http.StatusOK {
		t.Errorf("/public = %d, ingin 200", st)
	}
	if hit := got.under("/admin"); len(hit) != 0 {
		t.Errorf("path terlarang tersentuh: %v", hit)
	}
}

// Penilaian hanya pada request pertama berarti request kedua di koneksi yang sama
// lolos. Keep-alive adalah pola normal engine.
func TestIntercept_EveryRequestOnAConnectionIsChecked(t *testing.T) {
	_, got, host := tlsTarget(t)
	addr := startProxy(t, New(guardWith(t, []string{"127.0.0.1"}, []string{"https://" + host + "/admin"}), nil))

	tc := tlsTunnel(t, addr, host)
	fmt.Fprintf(tc, "GET /public HTTP/1.1\r\nHost: %s\r\n\r\nGET /admin HTTP/1.1\r\nHost: %s\r\n\r\nGET /again HTTP/1.1\r\nHost: %s\r\n\r\n", host, host, host)
	br := bufio.NewReader(tc)
	for i, want := range []int{http.StatusOK, http.StatusForbidden, http.StatusOK} {
		if st := readStatus(t, br); st != want {
			t.Errorf("respons #%d = %d, ingin %d", i+1, st, want)
		}
	}
	if hit := got.under("/admin"); len(hit) != 0 {
		t.Errorf("path terlarang tersentuh: %v", hit)
	}
}

// Redirect di dalam tunnel adalah request baru dan harus dinilai ulang.
func TestIntercept_RedirectIntoExcludedPathIsBlocked(t *testing.T) {
	got := &seenRequests{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.add(r)
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/admin/panel", http.StatusFound)
		}
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "https://")
	addr := startProxy(t, New(guardWith(t, []string{"127.0.0.1"}, []string{"https://" + host + "/admin"}), nil))

	if st := statusOf(t, insecureClient(t, addr), srv.URL+"/start"); st != http.StatusForbidden {
		t.Errorf("status akhir = %d, ingin 403", st)
	}
	if hit := got.under("/admin"); len(hit) != 0 {
		t.Errorf("redirect menembus eksklusi: %v", hit)
	}
}

// Tujuan ditentukan authority CONNECT yang sudah lolos guard, bukan tulisan klien.
func TestIntercept_DestinationIsAlwaysTheConnectAuthority(t *testing.T) {
	_, got, host := tlsTarget(t)
	_, other, otherHost := tlsTarget(t)
	addr := startProxy(t, New(guardWith(t, []string{"127.0.0.1"}, []string{"https://" + host + "/admin"}), nil))

	tc := tlsTunnel(t, addr, host)
	fmt.Fprintf(tc, "GET https://%s/x HTTP/1.1\r\nHost: %s\r\n\r\n", otherHost, otherHost)
	fmt.Fprintf(tc, "GET /y HTTP/1.1\r\nHost: %s\r\n\r\n", otherHost)
	fmt.Fprintf(tc, "GET https://%s/admin HTTP/1.1\r\nHost: %s\r\n\r\n", otherHost, otherHost)
	br := bufio.NewReader(tc)
	for i, want := range []int{http.StatusOK, http.StatusOK, http.StatusForbidden} {
		if st := readStatus(t, br); st != want {
			t.Errorf("respons #%d = %d, ingin %d", i+1, st, want)
		}
	}
	if n := len(other.list()); n != 0 {
		t.Errorf("host lain tersentuh %d kali: %v", n, other.list())
	}
	got.mu.Lock()
	defer got.mu.Unlock()
	for _, h := range got.hosts {
		if h != host {
			t.Errorf("Host diteruskan %q, ingin %q", h, host)
		}
	}
}

// Template unsafe nuclei bisa mengirim HTTP polos lewat CONNECT.
func TestIntercept_PlainHTTPInsideConnectIsChecked(t *testing.T) {
	got := &seenRequests{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got.add(r) }))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	addr := startProxy(t, New(guardWith(t, []string{"127.0.0.1"}, []string{"http://" + host + "/admin"}), nil))

	conn := openTunnel(t, addr, host)
	fmt.Fprintf(conn, "GET /admin HTTP/1.1\r\nHost: %s\r\n\r\nGET /public HTTP/1.1\r\nHost: %s\r\n\r\n", host, host)
	br := bufio.NewReader(conn)
	for i, want := range []int{http.StatusForbidden, http.StatusOK} {
		if st := readStatus(t, br); st != want {
			t.Errorf("respons #%d = %d, ingin %d", i+1, st, want)
		}
	}
	if hit := got.under("/admin"); len(hit) != 0 {
		t.Errorf("path terlarang tersentuh: %v", hit)
	}
}

// countingListener menghitung koneksi yang sampai: tunnel buta langsung menyambung
// saat CONNECT, jadi nol koneksi membuktikan tak ada jalan mundur.
func countingListener(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	n := &atomic.Int32{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			c.Close()
		}
	}()
	return ln.Addr().String(), n
}

func TestIntercept_UnreadableTrafficNeverFallsBackToBlindTunnel(t *testing.T) {
	cases := map[string]string{
		"bukan HTTP":     "\x00\x01 ini bukan http\r\n\r\n",
		"TLS rusak":      "\x16\x03\x01\x00\x05hallo-bukan-clienthello",
		"prefix HTTP/2":  "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
		"baris tak sah":  "GET\r\n\r\n",
		"tanpa Host 1.1": "GET /public HTTP/1.1\r\n\r\n",
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			host, accepted := countingListener(t)
			addr := startProxy(t, New(guardWith(t, []string{"127.0.0.1"}, []string{"http://" + host + "/admin"}), nil))

			conn := openTunnel(t, addr, host)
			io.WriteString(conn, payload)
			conn.SetDeadline(time.Now().Add(2 * time.Second))
			io.Copy(io.Discard, conn)
			if n := accepted.Load(); n != 0 {
				t.Errorf("%d koneksi sampai ke target", n)
			}
		})
	}
}

func TestIntercept_NestedConnectIsRefused(t *testing.T) {
	_, got, host := tlsTarget(t)
	_, other, otherHost := tlsTarget(t)
	addr := startProxy(t, New(guardWith(t, []string{"127.0.0.1"}, []string{"https://" + host + "/admin"}), nil))

	tc := tlsTunnel(t, addr, host)
	fmt.Fprintf(tc, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", otherHost, otherHost)
	if st := readStatus(t, bufio.NewReader(tc)); st != http.StatusMethodNotAllowed {
		t.Errorf("CONNECT bersarang = %d, ingin 405", st)
	}
	if n := len(got.list()) + len(other.list()); n != 0 {
		t.Errorf("request sampai ke target: %d", n)
	}
}

// Hanya tunnel yang dibuka mengambil alih peran engine. Jalur HTTP biasa tetap
// memverifikasi sertifikat.
func TestHandleHTTP_StillVerifiesTLS(t *testing.T) {
	_, got, host := tlsTarget(t)
	addr := startProxy(t, New(guardWith(t, []string{"127.0.0.1"}, nil), nil))

	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "GET https://%s/public HTTP/1.1\r\nHost: %s\r\n\r\n", host, host)
	if st := readStatus(t, bufio.NewReader(conn)); st != http.StatusBadGateway {
		t.Errorf("status = %d, ingin 502", st)
	}
	if n := len(got.list()); n != 0 {
		t.Errorf("backend kena %d kali", n)
	}
}

// HTTP/2 tak ditawarkan: hanya HTTP/1 yang bisa dinilai di sini.
func TestIntercept_OffersOnlyHTTP1(t *testing.T) {
	_, _, host := tlsTarget(t)
	addr := startProxy(t, New(guardWith(t, []string{"127.0.0.1"}, []string{"https://" + host + "/admin"}), nil))

	tc := tls.Client(openTunnel(t, addr, host), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if got := tc.ConnectionState().NegotiatedProtocol; got != "http/1.1" {
		t.Errorf("protokol = %q, ingin http/1.1", got)
	}
}

// Target opaque membuat URL.String mengabaikan Host, jadi yang dinilai guard bukan
// tujuan sebenarnya, dan path-nya dinilai tanpa percent-decode.
func TestIntercept_OpaqueRequestTargetIsRefused(t *testing.T) {
	host, accepted := countingListener(t)
	addr := startProxy(t, New(guardWith(t, []string{"127.0.0.1"}, []string{"http://" + host + "/admin"}), nil))

	conn := openTunnel(t, addr, host)
	fmt.Fprintf(conn, "GET http:x@127.0.0.1/public/%%2e%%2e/admin HTTP/1.1\r\nHost: %s\r\n\r\n", host)
	if st := readStatus(t, bufio.NewReader(conn)); st != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, ingin 405", st)
	}
	if n := accepted.Load(); n != 0 {
		t.Errorf("%d koneksi sampai ke target", n)
	}
}

// Sesudah 101 yang lewat bukan HTTP lagi, jadi tak ada path yang bisa dinilai. Tanpa
// penolakan, klien dan koneksi ke target menggantung selama target diam.
func TestIntercept_ProtocolUpgradeIsRefused(t *testing.T) {
	closed := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		rw.Flush()
		io.Copy(io.Discard, c)
		close(closed)
	}))
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "http://")
	addr := startProxy(t, New(guardWith(t, []string{"127.0.0.1"}, []string{"http://" + host + "/admin"}), nil))

	conn := openTunnel(t, addr, host)
	fmt.Fprintf(conn, "GET /ws HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n", host)
	if st := readStatus(t, bufio.NewReader(conn)); st != http.StatusBadGateway {
		t.Errorf("status = %d, ingin 502", st)
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Error("koneksi ke target tak ditutup")
	}
}

func TestIntercept_OnlyHostsWithPathExclusionAreOpened(t *testing.T) {
	srv, _, host := tlsTarget(t)
	_, port, _ := net.SplitHostPort(host)
	cases := []struct {
		name   string
		out    []string
		opened bool
	}{
		{"tanpa eksklusi", nil, false},
		{"eksklusi host lain", []string{"https://other.test/admin"}, false},
		{"eksklusi port lain", []string{"https://127.0.0.1:1/admin"}, false},
		{"eksklusi tepat", []string{"https://" + host + "/admin"}, true},
		{"eksklusi tanpa port", []string{"https://127.0.0.1/admin"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr := startProxy(t, New(guardWith(t, []string{"127.0.0.1"}, tc.out), nil))
			conn := tlsTunnel(t, addr, "127.0.0.1:"+port)
			blind := conn.ConnectionState().PeerCertificates[0].Equal(srv.Certificate())
			if blind == tc.opened {
				t.Errorf("sertifikat target asli=%v, ingin dibuka=%v", blind, tc.opened)
			}
		})
	}
}

func TestIntercept_DenialIsAuditedWithItsPath(t *testing.T) {
	srv, _, host := tlsTarget(t)
	var mu sync.Mutex
	var denied []Decision
	p := New(guardWith(t, []string{"127.0.0.1"}, []string{"https://" + host + "/admin"}), func(d Decision) {
		if !d.Allowed {
			mu.Lock()
			denied = append(denied, d)
			mu.Unlock()
		}
	})
	statusOf(t, insecureClient(t, startProxy(t, p)), srv.URL+"/admin/x")

	mu.Lock()
	defer mu.Unlock()
	if len(denied) != 1 {
		t.Fatalf("audit penolakan = %d, ingin 1: %+v", len(denied), denied)
	}
	d := denied[0]
	if d.Method != http.MethodGet || d.Reason != scope.ReasonOutOfScope || !strings.HasSuffix(d.Target, "/admin/x") {
		t.Errorf("audit tak tepat: %+v", d)
	}
	if n := len(p.Denials()); n != 1 {
		t.Errorf("Denials = %d, ingin 1", n)
	}
}

// Payload DAST harus sampai utuh; ReverseProxy akan membuang query bersemikolon
// dan menyentuh X-Forwarded-For, jadi keduanya dijaga di sini.
func TestIntercept_ForwardsRequestAndResponseIntact(t *testing.T) {
	type seen struct {
		uri, body, xff, cookie, encoding string
		hasEncoding                      bool
	}
	ch := make(chan seen, 1)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_, has := r.Header["Accept-Encoding"]
		ch <- seen{r.RequestURI, string(b), r.Header.Get("X-Forwarded-For"), r.Header.Get("Cookie"), r.Header.Get("Accept-Encoding"), has}
		w.Header().Set("X-Reply", "ya")
		w.Header().Add("Set-Cookie", "a=1")
		w.Header().Add("Set-Cookie", "b=2")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, "isi-respons")
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "https://")
	addr := startProxy(t, New(guardWith(t, []string{"127.0.0.1"}, []string{"https://" + host + "/admin"}), nil))

	uri := "/public/%2e%2e/x?a=1;b=2&c=%27"
	req, _ := http.NewRequest(http.MethodPost, srv.URL+uri, strings.NewReader("data=1'"))
	req.Header.Set("X-Forwarded-For", "10.9.8.7")
	req.Header.Set("Cookie", "sid=abc")
	resp, err := insecureClient(t, addr).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated || string(body) != "isi-respons" || resp.Header.Get("X-Reply") != "ya" || len(resp.Cookies()) != 2 {
		t.Errorf("respons berubah: %d %q %v", resp.StatusCode, body, resp.Header)
	}
	got := <-ch
	want := seen{uri: uri, body: "data=1'", xff: "10.9.8.7", cookie: "sid=abc"}
	if got != want {
		t.Errorf("request berubah:\n dapat %+v\n ingin %+v", got, want)
	}
}

func TestIntercept_TravelsThroughUpstreamChain(t *testing.T) {
	_, got, host := tlsTarget(t)
	var connects atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT saja", http.StatusBadRequest)
			return
		}
		connects.Add(1)
		dest, err := net.Dial("tcp", r.Host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		client, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			dest.Close()
			return
		}
		io.WriteString(client, "HTTP/1.1 200 OK\r\n\r\n")
		go pipe(dest, client)
		go pipe(client, dest)
	}))
	defer up.Close()

	p := New(guardWith(t, []string{"127.0.0.1"}, []string{"https://" + host + "/admin"}), nil)
	if err := p.SetUpstream(up.URL); err != nil {
		t.Fatal(err)
	}
	c := insecureClient(t, startProxy(t, p))
	if st := statusOf(t, c, "https://"+host+"/public"); st != http.StatusOK {
		t.Errorf("/public = %d, ingin 200", st)
	}
	if connects.Load() == 0 {
		t.Error("koneksi keluar harus lewat upstream")
	}
	if len(got.list()) != 1 {
		t.Errorf("backend kena %d kali, ingin 1", len(got.list()))
	}
}

// Membuka tunnel tak boleh melewati dialer ter-guard (anti SSRF & rebinding).
func TestIntercept_ForwardLegStillUsesGuardedDial(t *testing.T) {
	_, got, host := tlsTarget(t)
	_, port, _ := net.SplitHostPort(host)
	p := New(guardWith(t, []string{"demo.test"}, []string{"demo.test/admin"}), nil)
	p.lookupIP = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	c := insecureClient(t, startProxy(t, p))
	if st := statusOf(t, c, "https://demo.test:"+port+"/public"); st != http.StatusBadGateway {
		t.Errorf("status = %d, ingin 502", st)
	}
	if n := len(got.list()); n != 0 {
		t.Errorf("IP internal tersentuh %d kali", n)
	}
	var internal bool
	for _, d := range p.Denials() {
		internal = internal || d.Reason == scope.Reason("ip-internal")
	}
	if !internal {
		t.Errorf("penolakan ip-internal harus tercatat: %+v", p.Denials())
	}
}

func TestOriginHost(t *testing.T) {
	cases := []struct{ scheme, authority, want string }{
		{"https", "acme.io:443", "acme.io"},
		{"https", "acme.io:8443", "acme.io:8443"},
		{"https", "acme.io:80", "acme.io:80"},
		{"http", "acme.io:80", "acme.io"},
		{"http", "acme.io:443", "acme.io:443"},
		{"https", "[::1]:443", "[::1]"},
		{"https", "[::1]:8443", "[::1]:8443"},
	}
	for _, c := range cases {
		if got := originHost(c.scheme, c.authority); got != c.want {
			t.Errorf("originHost(%q, %q) = %q, ingin %q", c.scheme, c.authority, got, c.want)
		}
	}
}
