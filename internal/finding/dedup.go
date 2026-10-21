package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/url"
	"strings"
)

// ComputeDedupKey menghitung dedup_key deterministik sesuai resep v1 di
// BH-SPEC-FINDING:
//
//	sha256( lower(type) + "|" + host(target) + "|" + path(location.url) + "|" + (parameter|"") )
//
// Yang sengaja TIDAK masuk kunci: run_id, source_engine, timestamp, payload,
// dan nilai query. Dengan begitu isu yang sama pada parameter yang sama tetap
// satu temuan walau ditemukan dua engine atau di dua run berbeda.
func ComputeDedupKey(typ, target, locationURL, parameter string) string {
	raw := strings.ToLower(strings.TrimSpace(typ)) + "|" +
		hostOf(target) + "|" +
		pathOf(locationURL) + "|" +
		parameter
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// hostOf mengambil host dari target tanpa skema, userinfo, dan port. Dinormalkan
// huruf kecil dan tanpa titik akhir. Dedup v1 sengaja mengabaikan port (lihat
// pertanyaan terbuka penyempurnaan dedup_key di BH-SPEC-FINDING).
func hostOf(target string) string {
	t := strings.ToLower(strings.TrimSpace(target))
	if t == "" {
		return ""
	}
	p := t
	if !strings.Contains(p, "://") {
		p = "//" + p // beri url.Parse petunjuk bahwa ini authority, bukan path
	}
	if u, err := url.Parse(p); err == nil && u.Hostname() != "" {
		return strings.TrimSuffix(u.Hostname(), ".")
	}
	// Fallback kasar bila url.Parse gagal.
	h := strings.TrimPrefix(t, "//")
	if i := strings.IndexByte(h, '/'); i >= 0 {
		h = h[:i]
	}
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	}
	return strings.TrimSuffix(h, ".")
}

// pathOf mengambil path dari URL tanpa query string. Nilai query berubah-ubah
// antar scan sehingga tidak boleh ikut menentukan identitas temuan.
func pathOf(rawURL string) string {
	r := strings.TrimSpace(rawURL)
	if r == "" {
		return ""
	}
	if u, err := url.Parse(r); err == nil {
		return u.Path
	}
	if i := strings.IndexByte(r, '?'); i >= 0 {
		return r[:i]
	}
	return r
}
