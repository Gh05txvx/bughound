// Package engine mendefinisikan kontrak engine scan. Implementasi nyata
// mengeksekusi binary engine (nuclei, ZAP, dll) sebagai subprocess; implementasi
// mock mengembalikan hasil rekaman tanpa jaringan (dipakai di M0 & E2E).
//
// Hanya engine (worker) yang boleh menjangkau target, dan hanya target in-scope
// (BH-SPEC-SCOPE). Orchestrator menegakkan scope guard sebelum memanggil Scan
// dan memeriksa ulang setiap temuan yang keluar.
package engine

import (
	"context"
	"regexp"

	"bughound/internal/finding"
)

// logoutWord: route logout (logout, log-out, log_out, logoff, signout, sign-out,
// signoff, ...). Saat scan membawa header auth (AuthAware), crawler & engine
// MENGHINDARINYA: satu GET ke route logout mematikan sesi server-side dan sisa
// scan diam-diam jalan tanpa login (terbukti live 2026-11-16: katana, nuclei,
// ffuf, ZAP).
const logoutWord = `(log|sign)[-_]?(out|off)`

// LogoutPattern mencocokkan URL ABSOLUT yang path/query-nya route logout; host
// dilewati (catalogoutlet.com bukan logout). Sah untuk regex Go/katana (-cos)
// maupun Java/ZAP excludePaths (cocok-penuh — karena itu `.*` di ujung).
const LogoutPattern = `(?i)^[a-z][a-z0-9+.-]*://[^/?#]*[/?#].*` + logoutWord + `.*`

var (
	logoutURLRE  = regexp.MustCompile(LogoutPattern)
	logoutPathRE = regexp.MustCompile(`(?i)` + logoutWord)
)

// IsLogoutURL: URL absolut yang path/query-nya route logout. Host polos /
// host:port (tanpa skema) tak pernah dianggap logout.
func IsLogoutURL(u string) bool { return logoutURLRE.MatchString(u) }

// IsLogoutPath: path atau entri wordlist (tanpa skema/host) yang memuat route logout.
func IsLogoutPath(p string) bool { return logoutPathRE.MatchString(p) }

// Engine menjalankan satu engine terhadap satu target dan mengembalikan temuan
// yang sudah dinormalkan ke Skema Temuan Seragam (BH-SPEC-FINDING).
type Engine interface {
	Name() string
	Scan(ctx context.Context, target, program, runID string) ([]*finding.Finding, error)
}

// ProxyAware ditandai oleh engine yang koneksinya bisa diarahkan lewat proxy
// egress bughound (internal/egress). Orchestrator memanggil UseProxy sebelum
// Scan agar engine eksternal menegakkan scope guard pada setiap koneksi keluar
// (bukan hanya pemeriksaan setelah hasil). Engine mock tidak perlu ini.
type ProxyAware interface {
	UseProxy(addr string)
}

// OpenAPIAware ditandai oleh engine yang bisa memfuzz dari spesifikasi
// OpenAPI/Swagger (membangkitkan request lengkap termasuk BODY, bukan hanya
// query pada URL hasil crawl). Orchestrator memanggil UseOpenAPISpec sebelum Scan
// bila request membawa spec. Request yang dibangkitkan TETAP lewat proxy egress
// (scope guard menegakkan tiap koneksi; spec tak memintas batas).
type OpenAPIAware interface {
	UseOpenAPISpec(spec []byte)
}

// AuthAware ditandai oleh engine yang bisa menyertakan header autentikasi
// (mis. Cookie / Authorization) pada setiap request-nya, agar scan menjangkau
// konten di balik login (Lever 1: authenticated scanning). Orchestrator memanggil
// UseAuthHeaders sebelum Scan bila request membawa kredensial sesi. Tiap elemen
// berbentuk "Nama: nilai" (siap diteruskan sebagai `-H` ke tool).
//
// KEAMANAN: header hanya menumpang request yang SUDAH lolos scope guard. Bila
// engine mengikuti redirect ke host luar-scope, egress menolak dial sebelum
// koneksi sehingga kredensial tak pernah keluar scope. Nilai header adalah
// secret: jangan pernah dicetak ke log/temuan/report — orchestrator meredaksi
// nilainya dari evidence sebelum simpan (lihat Evidence.RedactHeaders).
type AuthAware interface {
	UseAuthHeaders(headers []string)
}
