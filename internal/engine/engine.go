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

	"bughound/internal/finding"
)

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
