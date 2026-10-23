package egress

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	xproxy "golang.org/x/net/proxy"
)

// dialFunc menyambung ke addr (host:port). addr adalah IP yang SUDAH diperiksa &
// di-pin oleh dialGuarded — rantai proxy hanya mengganti JALUR ke IP itu, bukan
// memintas scope guard maupun IP-pinning.
type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// buildChainDialer merantai proxy sesuai urutan (hop pertama → terakhir). Dial
// target berjalan: base → hop1 → hop2 → … → hopN → target; base me-reach hop1,
// tiap hop berikutnya di-reach lewat hop sebelumnya. Satu URL = rantai 1-hop.
// Skema tiap hop: http, https (CONNECT), socks5, socks5h; kredensial user:pass@host.
func buildChainDialer(urls []string, base *net.Dialer) (dialFunc, error) {
	var forward xproxy.Dialer = base
	count := 0
	for _, raw := range urls {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return nil, fmt.Errorf("egress: URL proxy tak valid: %q", raw)
		}
		d, err := hopDialer(u, forward)
		if err != nil {
			return nil, err
		}
		forward = d
		count++
	}
	if count == 0 {
		return nil, fmt.Errorf("egress: rantai proxy kosong")
	}
	final := forward
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialForward(ctx, final, addr)
	}, nil
}

// hopDialer membuat dialer yang menembus proxy u, dengan u sendiri di-reach via forward.
func hopDialer(u *url.URL, forward xproxy.Dialer) (xproxy.Dialer, error) {
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return &httpProxyDialer{u: u, forward: forward}, nil
	case "socks5", "socks5h":
		var auth *xproxy.Auth
		if u.User != nil {
			pw, _ := u.User.Password()
			auth = &xproxy.Auth{User: u.User.Username(), Password: pw}
		}
		return xproxy.SOCKS5("tcp", u.Host, auth, forward)
	default:
		return nil, fmt.Errorf("egress: skema proxy tak didukung: %q (pakai http/https/socks5)", u.Scheme)
	}
}

// dialForward menyambung ke addr lewat d, membawa ctx bila d mendukungnya
// (net.Dialer, SOCKS5, dan httpProxyDialer semuanya ContextDialer → ctx & pin
// IP terjaga di sepanjang rantai).
func dialForward(ctx context.Context, d xproxy.Dialer, addr string) (net.Conn, error) {
	if cd, ok := d.(xproxy.ContextDialer); ok {
		return cd.DialContext(ctx, "tcp", addr)
	}
	return d.Dial("tcp", addr)
}

// proxiedConn membungkus tunnel: Read lewat bufio (menampung sisa byte setelah
// header respons CONNECT), sisanya ke koneksi asli.
type proxiedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *proxiedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// httpProxyDialer menembus satu proxy HTTP(S) via CONNECT; proxy-nya di-reach
// lewat forward (hop sebelumnya atau base).
type httpProxyDialer struct {
	u       *url.URL
	forward xproxy.Dialer
}

func (h *httpProxyDialer) Dial(network, addr string) (net.Conn, error) {
	return h.DialContext(context.Background(), network, addr)
}

func (h *httpProxyDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	raw, err := dialForward(ctx, h.forward, h.u.Host)
	if err != nil {
		return nil, fmt.Errorf("egress: dial hop %s: %w", h.u.Host, err)
	}
	conn := net.Conn(raw)
	if strings.EqualFold(h.u.Scheme, "https") {
		tc := tls.Client(raw, &tls.Config{ServerName: hostOnly(h.u.Host)})
		if err := tc.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, fmt.Errorf("egress: TLS ke hop %s: %w", h.u.Host, err)
		}
		conn = tc
	}
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	var b strings.Builder
	fmt.Fprintf(&b, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", addr, addr)
	if h.u.User != nil {
		pw, _ := h.u.User.Password()
		cred := base64.StdEncoding.EncodeToString([]byte(h.u.User.Username() + ":" + pw))
		fmt.Fprintf(&b, "Proxy-Authorization: Basic %s\r\n", cred)
	}
	b.WriteString("\r\n")
	if _, err := conn.Write([]byte(b.String())); err != nil {
		conn.Close()
		return nil, err
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("egress: baca respons CONNECT hop %s: %w", h.u.Host, err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("egress: hop %s menolak CONNECT %s: %s", h.u.Host, addr, resp.Status)
	}
	_ = conn.SetDeadline(time.Time{})
	return &proxiedConn{Conn: conn, r: br}, nil
}
