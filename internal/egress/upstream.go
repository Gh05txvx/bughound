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
// di-pin oleh dialGuarded — upstream hanya mengganti JALUR ke IP itu, bukan
// memintas scope guard maupun IP-pinning.
type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// upstreamDialer membangun dialFunc yang menyambung lewat proxy upstream.
// Skema: http, https (CONNECT), socks5, socks5h. Kredensial via user:pass di URL.
func upstreamDialer(proxyURL string, base *net.Dialer) (dialFunc, error) {
	u, err := url.Parse(strings.TrimSpace(proxyURL))
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("egress: URL proxy upstream tak valid: %q", proxyURL)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return httpConnectDialer(u, base), nil
	case "socks5", "socks5h":
		var auth *xproxy.Auth
		if u.User != nil {
			pw, _ := u.User.Password()
			auth = &xproxy.Auth{User: u.User.Username(), Password: pw}
		}
		d, derr := xproxy.SOCKS5("tcp", u.Host, auth, base)
		if derr != nil {
			return nil, fmt.Errorf("egress: socks5: %w", derr)
		}
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			if cd, ok := d.(xproxy.ContextDialer); ok {
				return cd.DialContext(ctx, network, addr)
			}
			return d.Dial(network, addr)
		}, nil
	default:
		return nil, fmt.Errorf("egress: skema proxy upstream tak didukung: %q (pakai http/https/socks5)", u.Scheme)
	}
}

// proxiedConn membungkus koneksi tunnel: Read lewat bufio (menampung sisa byte
// setelah header respons CONNECT), sisanya diteruskan ke koneksi asli.
type proxiedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *proxiedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func httpConnectDialer(u *url.URL, base *net.Dialer) dialFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		raw, err := base.DialContext(ctx, "tcp", u.Host)
		if err != nil {
			return nil, fmt.Errorf("egress: dial upstream %s: %w", u.Host, err)
		}
		conn := net.Conn(raw)
		if strings.EqualFold(u.Scheme, "https") {
			tc := tls.Client(raw, &tls.Config{ServerName: hostOnly(u.Host)})
			if err := tc.HandshakeContext(ctx); err != nil {
				raw.Close()
				return nil, fmt.Errorf("egress: TLS ke upstream: %w", err)
			}
			conn = tc
		}
		_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

		var b strings.Builder
		fmt.Fprintf(&b, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", addr, addr)
		if u.User != nil {
			pw, _ := u.User.Password()
			cred := base64.StdEncoding.EncodeToString([]byte(u.User.Username() + ":" + pw))
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
			return nil, fmt.Errorf("egress: baca respons CONNECT upstream: %w", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			conn.Close()
			return nil, fmt.Errorf("egress: upstream CONNECT %s menolak: %s", addr, resp.Status)
		}
		_ = conn.SetDeadline(time.Time{}) // bersihkan deadline untuk tunnel
		return &proxiedConn{Conn: conn, r: br}, nil
	}
}
