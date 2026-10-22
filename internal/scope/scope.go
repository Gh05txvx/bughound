// Package scope mengimplementasikan Scope Guard (BH-SPEC-SCOPE): kontrol
// keamanan paling kritis di bughound. Ia menjawab satu pertanyaan untuk setiap
// target — boleh disentuh atau tidak — dengan sikap paling konservatif.
//
// Prinsip yang ditegakkan kode ini:
//   - Default deny: bila tidak terbukti in-scope, tolak.
//   - Out-of-scope menang: cocok in-scope sekaligus out-of-scope => tolak.
//   - Fail closed: target/scope yang gagal diurai => tolak, bukan loloskan.
//   - Deterministik: input sama selalu memberi keputusan sama.
//   - Satu titik keputusan: Evaluate dipakai baik di lapis input maupun egress.
//
// Guard ini tidak melakukan resolusi DNS di v1 (lihat pertanyaan terbuka DNS
// rebinding di BH-SPEC-SCOPE): target berupa hostname dicocokkan sebagai
// hostname, target berupa IP dicocokkan sebagai IP.
package scope

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path"
	"strings"

	"golang.org/x/net/idna"
)

// Reason menjelaskan kenapa sebuah keputusan diambil (untuk audit trail).
type Reason string

const (
	ReasonInScope    Reason = "in-scope"
	ReasonOutOfScope Reason = "out-of-scope"
	ReasonNotInScope Reason = "tidak in-scope"
	ReasonParseError Reason = "gagal urai"
)

// Result adalah keputusan guard untuk satu target. Field-nya cukup untuk
// dicatat ke audit trail sesuai BH-SPEC-SCOPE (target ternormalkan, alasan,
// dan entri scope pemicu bila penolakan karena out-of-scope).
type Result struct {
	Allowed      bool
	Reason       Reason
	Target       string // target ternormalkan (untuk audit)
	MatchedEntry string // entri scope pemicu (izin/tolak), kosong bila default deny
}

// Guard menyimpan entri in-scope dan out-of-scope yang sudah dikompilasi.
type Guard struct {
	in  []entry
	out []entry
}

// New mengompilasi dua daftar scope menjadi Guard. Entri yang tidak bisa diurai
// TIDAK diam-diam diabaikan: ia dikembalikan sebagai error agar pengguna diberi
// tahu (BH-SPEC-SCOPE: "ditolak saat input, pengguna diberi tahu").
//
// Pemanggil WAJIB memperlakukan errs yang tidak kosong sebagai penghalang:
// jangan jalankan scan dengan scope yang separuh terurai — khususnya entri
// out-of-scope yang gagal diurai berarti under-blocking.
func New(inScope, outScope []string) (g *Guard, errs []error) {
	g = &Guard{}
	for _, raw := range inScope {
		e, err := parseEntry(raw)
		if err != nil {
			errs = append(errs, fmt.Errorf("in-scope: %w", err))
			continue
		}
		g.in = append(g.in, e)
	}
	for _, raw := range outScope {
		e, err := parseEntry(raw)
		if err != nil {
			errs = append(errs, fmt.Errorf("out-of-scope: %w", err))
			continue
		}
		g.out = append(g.out, e)
	}
	return g, errs
}

// Evaluate mengambil keputusan untuk satu target. Urutannya penting: out-of-scope
// diperiksa lebih dulu agar selalu menang, lalu in-scope, lalu default deny.
// Normalisasi selalu dijalankan dulu; bila gagal, hasilnya tolak (fail closed).
func (g *Guard) Evaluate(target string) Result {
	t, err := normalizeTarget(target)
	if err != nil {
		return Result{Allowed: false, Reason: ReasonParseError, Target: strings.TrimSpace(target)}
	}
	norm := t.String()

	for _, e := range g.out {
		if e.matches(t) {
			return Result{Allowed: false, Reason: ReasonOutOfScope, Target: norm, MatchedEntry: e.raw}
		}
	}
	for _, e := range g.in {
		if e.matches(t) {
			return Result{Allowed: true, Reason: ReasonInScope, Target: norm, MatchedEntry: e.raw}
		}
	}
	return Result{Allowed: false, Reason: ReasonNotInScope, Target: norm}
}

// normTarget adalah target yang sudah dinormalkan ke bentuk kanonik.
type normTarget struct {
	isIP bool
	addr netip.Addr // bila isIP
	host string     // host punycode huruf kecil, bila !isIP
	port string     // "" bila tak disebut
	path string     // path ternormalkan, "/" bila tak ada
}

func (t normTarget) String() string {
	h := t.host
	if t.isIP {
		h = t.addr.String()
	}
	if t.port != "" {
		h = net.JoinHostPort(h, t.port)
	}
	if t.path != "" && t.path != "/" {
		h += t.path
	}
	return h
}

// normalizeTarget mengurai target (dengan atau tanpa skema) menjadi bentuk
// kanonik. Userinfo (user:pass@) dibuang; host IDN diubah ke punycode; IP
// diurai secara numerik.
func normalizeTarget(target string) (normTarget, error) {
	s := strings.TrimSpace(target)
	if s == "" {
		return normTarget{}, errors.New("target kosong")
	}
	if hasSuspiciousChars(s) {
		return normTarget{}, fmt.Errorf("target mengandung karakter terlarang (backslash/spasi/kontrol): %q", target)
	}
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil || u.Host == "" {
			return normTarget{}, fmt.Errorf("target URL tak valid: %q", target)
		}
		return finishTarget(u.Hostname(), u.Port(), u.Path)
	}
	hostport, p := s, ""
	if i := strings.IndexByte(s, '/'); i >= 0 {
		hostport, p = s[:i], s[i:]
	}
	if at := strings.LastIndexByte(hostport, '@'); at >= 0 {
		hostport = hostport[at+1:] // buang userinfo
	}
	host, port, err := splitHostPort(hostport)
	if err != nil {
		return normTarget{}, err
	}
	return finishTarget(host, port, p)
}

func finishTarget(host, port, rawPath string) (normTarget, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return normTarget{isIP: true, addr: addr, port: port, path: normalizePath(rawPath)}, nil
	}
	h, err := normalizeHost(host)
	if err != nil {
		return normTarget{}, err
	}
	return normTarget{host: h, port: port, path: normalizePath(rawPath)}, nil
}

// normalizeHost menurunkan host ke bentuk kanonik: huruf kecil, tanpa titik
// akhir, dan dikonversi ke punycode (xn--). Konversi punycode inilah yang
// menutup bypass homoglyph/IDN: host Cyrillic "аcme.io" jadi label punycode
// berbeda yang tidak akan cocok dengan "acme.io", atau ditolak idna — keduanya
// fail closed.
func normalizeHost(h string) (string, error) {
	h = strings.TrimSuffix(strings.TrimSpace(h), ".")
	if h == "" {
		return "", errors.New("host kosong")
	}
	ascii, err := idna.Lookup.ToASCII(h)
	if err != nil {
		return "", fmt.Errorf("normalisasi host %q: %w", h, err)
	}
	return strings.ToLower(ascii), nil
}

// normalizePath menormalkan path: selalu absolut, resolusi "."/".." dan slash
// ganda dihilangkan, trailing slash dibuang (kecuali root). url.Parse sudah
// melakukan percent-decoding yang aman untuk path dari URL.
func normalizePath(p string) string {
	if p == "" || p == "/" {
		return "/"
	}
	return path.Clean("/" + strings.TrimLeft(p, "/"))
}

// hasSuspiciousChars melaporkan apakah s memuat karakter yang rawan membuat
// parser berbeda menafsirkan authority berbeda (backslash, spasi, kontrol, DEL).
// Hostname/URL scope yang sah tidak pernah memuat karakter ini (BH-F04).
func hasSuspiciousChars(s string) bool {
	for _, r := range s {
		if r == '\\' || r <= 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// splitHostPort memisahkan host dan port secara IPv6-aware. IP tanpa port
// (termasuk IPv6 tanpa kurung) dikembalikan apa adanya; IPv6 dengan port wajib
// pakai notasi kurung "[::1]:8080".
func splitHostPort(s string) (host, port string, err error) {
	if s == "" {
		return "", "", errors.New("host kosong")
	}
	if strings.HasPrefix(s, "[") {
		return net.SplitHostPort(s)
	}
	if _, e := netip.ParseAddr(s); e == nil {
		return s, "", nil // IP mentah (v4 atau v6 tanpa kurung/port)
	}
	if strings.Count(s, ":") == 1 {
		return net.SplitHostPort(s)
	}
	if strings.Contains(s, ":") {
		return "", "", fmt.Errorf("host:port ambigu: %q", s)
	}
	return s, "", nil
}
