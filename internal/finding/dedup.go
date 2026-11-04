package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/url"
	"strings"
)

// ComputeDedupKey menghitung dedup_key deterministik di BH-SPEC-FINDING:
//
//	sha256( lower(type) | host(target) | path(location.url) | METHOD | (parameter|"") )
//
// METHOD (GET/POST/...) ikut menentukan identitas agar dua isu berbeda pada
// path+parameter yang sama tetapi method berbeda (mis. GET vs POST) tidak salah
// gabung. Method dinormalkan ke huruf besar; kosong (engine yang tak
// melaporkannya, mis. ffuf/retire/SAST) tetap kosong, jadi perilaku untuk
// engine itu tak berubah satu sama lain.
//
// Yang sengaja TIDAK masuk kunci: run_id, source_engine, timestamp, payload,
// dan nilai query. Dengan begitu isu yang sama pada parameter+method yang sama
// tetap satu temuan walau ditemukan dua engine atau di dua run berbeda.
//
// Pengecualian: untuk tipe SITE-WIDE (lihat siteWide) path DAN method
// dikeluarkan dari kunci (identitas = origin). Isu origin-level seperti header
// CSP/HSTS absen atau CORS permisif dilaporkan engine (mis. ZAP) sekali per URL
// yang dirayapi, padahal satu origin = satu misconfig. Mengabaikan path & method
// membuat semua instance terkolaps jadi satu temuan utama; sisanya ditandai
// duplikat oleh store (disembunyikan dari hitungan & report, tetap tersimpan
// utuh untuk audit).
func ComputeDedupKey(typ, target, locationURL, method, parameter string) string {
	path := pathOf(locationURL)
	meth := normMethod(method)
	if siteWide(typ) {
		path = "" // identitas = origin, bukan path
		meth = "" // isu origin-level tak spesifik per method
	}
	raw := strings.ToLower(strings.TrimSpace(typ)) + "|" +
		hostOf(target) + "|" +
		path + "|" +
		meth + "|" +
		parameter
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// normMethod menormalkan method HTTP ke huruf besar tanpa spasi tepi (mis.
// "get" -> "GET"); string kosong tetap kosong. Menjaga kunci konsisten walau
// engine melaporkan casing berbeda.
func normMethod(m string) string {
	return strings.ToUpper(strings.TrimSpace(m))
}

// siteWideTypes: tipe isu yang identitasnya ORIGIN (host), bukan path tertentu.
// Disengaja sebagai daftar eksplisit + pola sufiks konservatif agar temuan
// per-path yang sah (exposed-path, suspicious-comments per berkas, dll.) TIDAK
// pernah ikut terkolaps keliru.
var siteWideTypes = map[string]bool{
	"cross-domain-misconfiguration": true, // CORS permisif (origin-level)
	"modern-web-application":        true, // info ZAP, sama utk seluruh situs
	"user-agent-fuzzer":             true, // probe header, bukan path spesifik
}

// siteWide melaporkan apakah typ adalah isu origin-level yang dedup-nya harus
// mengabaikan path. Keluarga header-policy ZAP ("...-header-not-set" /
// "...-header-missing", mis. CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
// selalu origin-level, begitu pula kebocoran teknologi via X-Powered-By.
func siteWide(typ string) bool {
	t := strings.ToLower(strings.TrimSpace(typ))
	if siteWideTypes[t] {
		return true
	}
	return strings.HasSuffix(t, "-header-not-set") ||
		strings.HasSuffix(t, "-header-missing") ||
		strings.Contains(t, "x-powered-by")
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
