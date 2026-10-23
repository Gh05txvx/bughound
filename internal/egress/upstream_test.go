package egress

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"bughound/internal/scope"
)

// fakeConnectProxy menerima CONNECT dan menyalurkan ke tujuan.
func fakeConnectProxy(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil || req.Method != http.MethodConnect {
					c.Close()
					return
				}
				dst, err := net.Dial("tcp", req.Host)
				if err != nil {
					c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
					c.Close()
					return
				}
				c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
				go func() { io.Copy(dst, br); dst.Close() }()
				go func() { io.Copy(c, dst); c.Close() }()
			}(c)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func echoServer(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { io.Copy(c, c); c.Close() }(c)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func TestUpstreamHTTPConnectTunnels(t *testing.T) {
	proxyAddr, stopP := fakeConnectProxy(t)
	defer stopP()
	target, stopT := echoServer(t)
	defer stopT()

	dial, err := upstreamDialer("http://"+proxyAddr, &net.Dialer{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dial(context.Background(), "tcp", target)
	if err != nil {
		t.Fatalf("dial via upstream: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("baca echo: %v", err)
	}
	if string(buf) != "ping" {
		t.Errorf("echo via upstream = %q, ingin ping", buf)
	}
}

func TestUpstreamBadScheme(t *testing.T) {
	if _, err := upstreamDialer("ftp://x:1", &net.Dialer{}); err == nil {
		t.Error("skema tak didukung harus error")
	}
	if _, err := upstreamDialer("::bad::", &net.Dialer{}); err == nil {
		t.Error("URL tak valid harus error")
	}
}

func TestUpstreamSOCKS5Constructs(t *testing.T) {
	if _, err := upstreamDialer("socks5://127.0.0.1:9050", &net.Dialer{}); err != nil {
		t.Errorf("socks5 harus terbentuk: %v", err)
	}
}

func TestSetUpstream(t *testing.T) {
	g, _ := scope.New([]string{"demo.test"}, nil)
	p := New(g, nil)
	if err := p.SetUpstream("http://127.0.0.1:8080"); err != nil || p.finalDial == nil {
		t.Fatalf("SetUpstream http harus memasang finalDial: %v", err)
	}
	if err := p.SetUpstream(""); err != nil || p.finalDial != nil {
		t.Fatalf("URL kosong harus mengosongkan finalDial: %v", err)
	}
	if err := p.SetUpstream("bogus://x"); err == nil {
		t.Error("skema bogus harus error")
	}
}
