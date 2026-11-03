package egress

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Diagnostik proxy/egress untuk menu "Proxy": menguji rantai & memperlihatkan IP
// yang dilihat target (langsung vs lewat rantai). BUKAN jalur scan:
//   - TestChain hanya menyentuh infrastruktur proxy (hop) milik operator, tak
//     pernah target scan.
//   - Fetch menegakkan scope guard atas URL echo PERSIS seperti engine nyata
//     (default-deny, dicatat audit) sebelum koneksi.
//
// Kredensial proxy (user:pass@) tidak pernah ditampilkan, dicatat, atau
// dikembalikan — hanya dipakai internal untuk mendial (Prinsip #5).

// HopStatus adalah hasil uji satu hop proxy (resolusi DNS + konektivitas).
type HopStatus struct {
	Index       int
	Display     string // scheme://host[:port] TANPA kredensial
	Scheme      string
	ResolvedIPs []string
	Reachable   bool
	LatencyMS   int64
	Err         string
}

var (
	credRe = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.\-]*://)[^/@\s]*@`)
	ipRe   = regexp.MustCompile(`(?:\d{1,3}\.){3}\d{1,3}|(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}`)
)

// redactCreds membuang userinfo (scheme://user:pass@ -> scheme://) dari string
// apa pun (error/URL) agar kredensial tak bocor.
func redactCreds(s string) string { return credRe.ReplaceAllString(s, "$1") }

// ExtractClientIP mengambil token IP pertama dari body echo (teks polos atau
// JSON seperti {"ip":"1.2.3.4"}). Kosong bila tak ada.
func ExtractClientIP(body string) string { return ipRe.FindString(body) }

func redactProxyURL(u *url.URL) string { return strings.ToLower(u.Scheme) + "://" + u.Host }

// ParseChain mem-parse & memvalidasi tiap hop (skema didukung + host ada). Error
// merujuk NOMOR hop, tak pernah meng-echo baris mentah (bisa memuat kredensial).
func ParseChain(hops []string) ([]*url.URL, error) {
	var out []*url.URL
	for i, raw := range hops {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return nil, fmt.Errorf("hop #%d: URL proxy tak valid", i+1)
		}
		switch strings.ToLower(u.Scheme) {
		case "http", "https", "socks5", "socks5h":
		default:
			return nil, fmt.Errorf("hop #%d: skema %q tak didukung (pakai http/https/socks5)", i+1, u.Scheme)
		}
		out = append(out, u)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("rantai proxy kosong")
	}
	return out, nil
}

// TestChain menguji konektivitas tiap hop berurutan: hop_i di-reach lewat
// hop_1..hop_{i-1} (hop_1 langsung dari host ini), dan me-resolve host tiap hop.
// Tidak menyentuh target scan apa pun — hanya proxy milik operator.
func TestChain(ctx context.Context, hops []*url.URL, timeout time.Duration) []HopStatus {
	base := &net.Dialer{Timeout: timeout}
	raw := make([]string, len(hops))
	for i, u := range hops {
		raw[i] = u.String()
	}
	out := make([]HopStatus, 0, len(hops))
	for i, u := range hops {
		st := HopStatus{Index: i + 1, Display: redactProxyURL(u), Scheme: strings.ToLower(u.Scheme)}

		rctx, cancel := context.WithTimeout(ctx, timeout)
		if ips, err := net.DefaultResolver.LookupNetIP(rctx, "ip", hostOnly(u.Host)); err == nil {
			for _, ip := range ips {
				st.ResolvedIPs = append(st.ResolvedIPs, ip.String())
			}
		}
		cancel()

		var dial dialFunc = base.DialContext
		if i > 0 {
			d, err := buildChainDialer(raw[:i], base)
			if err != nil {
				st.Err = redactCreds(err.Error())
				out = append(out, st)
				continue
			}
			dial = d
		}

		dctx, cancel2 := context.WithTimeout(ctx, timeout)
		start := time.Now()
		conn, err := dial(dctx, "tcp", u.Host)
		st.LatencyMS = time.Since(start).Milliseconds()
		cancel2()
		if err != nil {
			st.Err = redactCreds(err.Error())
		} else {
			st.Reachable = true
			_ = conn.Close()
		}
		out = append(out, st)
	}
	return out
}

// FetchResult adalah hasil satu GET lewat jalur egress ter-guard.
type FetchResult struct {
	Allowed bool
	Reason  string
	Status  int
	Body    string // dipangkas
	Err     string
}

// Fetch melakukan GET rawURL lewat jalur egress ter-guard: scope guard dievaluasi
// atas URL (default-deny, dicatat audit) SEBELUM koneksi, lalu dial ter-guard +
// IP-pin + rantai upstream bila sudah di-set via SetUpstream. Dipakai diagnostik
// "cek IP egress". Body dibatasi 4 KiB agar aman.
func (p *Proxy) Fetch(ctx context.Context, rawURL string, timeout time.Duration) *FetchResult {
	d := p.guard.Evaluate(rawURL)
	host := ""
	if u, err := url.Parse(rawURL); err == nil {
		host = u.Hostname()
	}
	p.record(Decision{Method: "GET", Host: host, Target: d.Target, Allowed: d.Allowed, Reason: d.Reason})
	if !d.Allowed {
		return &FetchResult{Allowed: false, Reason: string(d.Reason)}
	}
	client := &http.Client{Transport: p.transport, Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return &FetchResult{Allowed: true, Err: redactCreds(err.Error())}
	}
	resp, err := client.Do(req)
	if err != nil {
		return &FetchResult{Allowed: true, Err: redactCreds(err.Error())}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	return &FetchResult{Allowed: true, Status: resp.StatusCode, Body: strings.TrimSpace(string(b))}
}
