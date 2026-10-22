package egress

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"bughound/internal/scope"
)

func mustGuard(t *testing.T, in []string) *scope.Guard {
	t.Helper()
	g, errs := scope.New(in, nil)
	if len(errs) > 0 {
		t.Fatalf("scope.New: %v", errs)
	}
	return g
}

func proxyClient(t *testing.T, addr string) *http.Client {
	t.Helper()
	pu, _ := url.Parse("http://" + addr)
	return &http.Client{
		Timeout:   3 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(pu)},
	}
}

func TestProxyAllowsInScopeHTTP(t *testing.T) {
	var hits int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Write([]byte("ok"))
	}))
	defer backend.Close()
	bu, _ := url.Parse(backend.URL)

	p := New(mustGuard(t, []string{bu.Hostname()}), nil) // 127.0.0.1 in-scope
	addr, stop, err := p.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	resp, err := proxyClient(t, addr).Get(backend.URL)
	if err != nil {
		t.Fatalf("GET lewat proxy: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d, ingin 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Errorf("body=%q", body)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Errorf("backend harus kena 1x, dapat %d", hits)
	}
}

func TestProxyDeniesOutOfScopeHTTP(t *testing.T) {
	var hits int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer backend.Close()

	var mu sync.Mutex
	var decisions []Decision
	// Backend 127.0.0.1 TIDAK in-scope (hanya example.test).
	p := New(mustGuard(t, []string{"example.test"}), func(d Decision) {
		mu.Lock()
		decisions = append(decisions, d)
		mu.Unlock()
	})
	addr, stop, _ := p.Listen("127.0.0.1:0")
	defer stop()

	resp, err := proxyClient(t, addr).Get(backend.URL)
	if err != nil {
		t.Fatalf("permintaan harus dapat 403, bukan error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d, ingin 403", resp.StatusCode)
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Error("backend di luar scope TIDAK boleh tersentuh")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(decisions) != 1 || decisions[0].Allowed {
		t.Errorf("harus ada 1 keputusan tolak; dapat %+v", decisions)
	}
	if len(p.Denials()) != 1 {
		t.Errorf("Denials harus mencatat 1; dapat %d", len(p.Denials()))
	}
}

func TestProxyConnectDeniedOutOfScope(t *testing.T) {
	p := New(mustGuard(t, []string{"example.test"}), nil)
	addr, stop, _ := p.Listen("127.0.0.1:0")
	defer stop()

	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	req, _ := http.NewRequest("CONNECT", "https://evil.test:443", nil)
	req.Host = "evil.test:443"
	if err := req.Write(conn); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("CONNECT di luar scope harus 403; dapat %d", resp.StatusCode)
	}
}

func TestProxyConnectTunnelInScope(t *testing.T) {
	// Server TCP echo sebagai tujuan in-scope.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go io.Copy(c, c) // echo
		}
	}()
	echoHost, _, _ := net.SplitHostPort(ln.Addr().String())

	p := New(mustGuard(t, []string{echoHost}), nil) // 127.0.0.1 in-scope
	addr, stop, _ := p.Listen("127.0.0.1:0")
	defer stop()

	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	req, _ := http.NewRequest("CONNECT", "https://"+ln.Addr().String(), nil)
	req.Host = ln.Addr().String()
	if err := req.Write(conn); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("CONNECT in-scope harus 200; dapat %d", resp.StatusCode)
	}
	// Tunnel aktif: tulis lalu baca echo.
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatalf("baca echo: %v", err)
	}
	if string(buf) != "ping" {
		t.Errorf("echo=%q, ingin ping", buf)
	}
}
