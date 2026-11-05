package egress

// Penegakan path di dalam tunnel.
//
// CONNECT hanya memperlihatkan host:port, padahal eksklusi bisa ber-path. Untuk
// host:port yang punya eksklusi seperti itu, proxy tidak membuat tunnel buta: ia
// membuka koneksi klien dan menjalankan tiap request di dalamnya lewat gerbang
// yang sama dengan HTTP biasa (forward). Host lain tetap tunnel buta, sehingga
// scan tanpa eksklusi ber-path tak berubah.
//
// Tak ada jalan mundur: koneksi yang tak bisa dibuka atau tak terbaca sebagai
// HTTP ditutup, bukan diteruskan, karena byte yang tak terbaca tak bisa dinilai.
//
// Sertifikat sekali pakai cukup: engine memang tak memverifikasi sertifikat target,
// jadi tak ada klien yang perlu mempercayainya. Kuncinya hanya hidup di memori
// selama proxy hidup.

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	tlsHandshakeRecord = 0x16 // byte pertama ClientHello

	tunnelReadTimeout = 30 * time.Second
	tunnelIdleTimeout = 2 * time.Minute
)

// serveOpened menjalankan koneksi klien hasil CONNECT sebagai server HTTP milik
// proxy. Isi tunnel tak harus TLS, jadi HTTP polos ikut ditangani. br menampung
// byte yang sudah terbaca saat hijack.
func (p *Proxy) serveOpened(conn net.Conn, br *bufio.Reader, authority string) {
	conn.SetReadDeadline(time.Now().Add(tunnelReadTimeout))
	first, err := br.Peek(1)
	conn.SetReadDeadline(time.Time{})
	if err != nil {
		conn.Close()
		return
	}

	scheme := "http"
	var c net.Conn = &proxiedConn{Conn: conn, r: br}
	if first[0] == tlsHandshakeRecord {
		cert, err := p.tunnelCert()
		if err != nil {
			conn.Close()
			return
		}
		scheme = "https"
		c = tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
	}

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p.serveTunneled(w, r, scheme, authority)
		}),
		ReadHeaderTimeout: tunnelReadTimeout,
		IdleTimeout:       tunnelIdleTimeout,
		ErrorLog:          log.New(io.Discard, "", 0), // galat klien bukan urusan log server
	}
	_ = srv.Serve(&oneConnListener{conn: c, addr: conn.LocalAddr()})
}

// serveTunneled menilai satu request dari tunnel yang dibuka.
func (p *Proxy) serveTunneled(w http.ResponseWriter, r *http.Request, scheme, authority string) {
	// CONNECT bersarang bisa menuju host lain, HTTP/2 tak punya path terbaca, dan
	// target opaque membuat URL.String mengabaikan Host yang disetel di bawah.
	if r.Method == http.MethodConnect || r.ProtoMajor != 1 || r.URL.Opaque != "" {
		http.Error(w, "egress ditolak: bentuk request tak didukung di dalam tunnel", http.StatusMethodNotAllowed)
		return
	}
	// Tujuan selalu authority CONNECT yang sudah lolos guard. URL absolut dan Host
	// tulisan klien tak boleh membelokkannya, sama seperti URL absolut di HTTP biasa
	// yang mengalahkan header Host.
	r.URL.Scheme = scheme
	r.URL.Host = originHost(scheme, authority)
	r.Host = r.URL.Host
	p.forward(w, r, p.tunnel)
}

// originHost membuang port bawaan skema. Tanpa ini header Host menjadi
// "acme.io:443", yang bisa mengubah perilaku aplikasi target.
func originHost(scheme, authority string) string {
	if scheme == "https" {
		return strings.TrimSuffix(authority, ":443")
	}
	return strings.TrimSuffix(authority, ":80")
}

func (p *Proxy) tunnelCert() (tls.Certificate, error) {
	p.certOnce.Do(func() { p.cert, p.certErr = newTunnelCert() })
	return p.cert, p.certErr
}

func newTunnelCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "bughound egress"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// oneConnListener menyerahkan satu koneksi ke http.Server, lalu berhenti. Koneksi
// itu tetap dilayani sesudah Serve kembali.
type oneConnListener struct {
	conn net.Conn
	addr net.Addr
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	if l.conn == nil {
		return nil, io.EOF
	}
	c := l.conn
	l.conn = nil
	return c, nil
}

func (l *oneConnListener) Close() error   { return nil }
func (l *oneConnListener) Addr() net.Addr { return l.addr }
