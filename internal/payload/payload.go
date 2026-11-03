// Package payload mengimplementasikan Bank Payload & Template (BH-SPEC-PAYLOAD):
// satu lapisan KATALOG netral di atas template native tiap engine. Isi payload
// tidak pernah diterjemahkan — template nuclei tetap YAML nuclei — bughound
// hanya menambahkan metadata seragam yang mengatalogkan tiap template sehingga
// bank bisa difilter, diperbarui, ditambah, dan dilacak balik.
//
// Model: "hibrida condong tipis" (BH-SPEC-PAYLOAD §Model yang dipilih). Paket ini
// MEMBACA sumber (direktori template) dan membangun katalog; ia tidak menjalankan
// apa pun dan tidak membuka koneksi jaringan. Eksekusi tetap milik engine adapter,
// dan setiap koneksi keluar tetap melewati scope guard (BH-SPEC-SCOPE) — template
// tak bisa memintas scope.
//
// Ketertelusuran: template_id di katalog berbentuk "<engine>:<native-id>" dan
// itulah nilai yang terbawa ke field source_template pada temuan
// (BH-SPEC-FINDING), sehingga tiap temuan bisa dilacak balik ke payload asalnya.
package payload

import (
	"strings"
	"time"

	"bughound/internal/finding"
)

// Trust adalah tingkat kepercayaan sumber template (BH-SPEC-PAYLOAD §Keamanan).
// Hanya sumber `trusted` yang templatenya boleh aktif (enabled) secara otomatis;
// `review`/`untrusted` masuk katalog dalam keadaan nonaktif sampai ditinjau dan
// dinaikkan trust-nya secara sadar.
type Trust string

const (
	TrustTrusted   Trust = "trusted"
	TrustReview    Trust = "review"
	TrustUntrusted Trust = "untrusted"
)

// Valid melaporkan apakah t salah satu tingkat trust yang sah.
func (t Trust) Valid() bool {
	switch t {
	case TrustTrusted, TrustReview, TrustUntrusted:
		return true
	}
	return false
}

// Safety mengklasifikasi dampak payload terhadap target (BH-SPEC-PAYLOAD
// §Keamanan, aditif). Dipakai untuk memfilter payload yang berpotensi MENGUBAH
// state/konfigurasi target: alur bug bounty bughound mencari kandidat bug untuk
// diverifikasi manual, bukan mengeksekusi sampai merusak.
type Safety string

const (
	// SafetyReadOnly: payload deteksi yang tak mengubah state (probe boolean/
	// time/error, cek refleksi). Default untuk template nuclei pada umumnya.
	SafetyReadOnly Safety = "read-only"
	// SafetyMutating: berpotensi mengubah/merusak (mis. DoS, tag intrusive/
	// destructive). Tidak dijalankan engine DAST secara default.
	SafetyMutating Safety = "mutating"
)

// Valid melaporkan apakah s salah satu nilai safety yang sah.
func (s Safety) Valid() bool { return s == SafetyReadOnly || s == SafetyMutating }

// mutatingTags adalah penanda tag yang menandakan payload mengubah/merusak.
// Konservatif dan bisa diperluas; selaras dengan destructiveExcludeTags engine.
var mutatingTags = map[string]bool{"dos": true, "intrusive": true, "destructive": true}

// classifySafety menurunkan Safety dari tag template: mutating bila ada penanda
// berbahaya, selain itu read-only (template nuclei mayoritas deteksi/read-only).
func classifySafety(tags []string) Safety {
	for _, t := range tags {
		if mutatingTags[strings.ToLower(strings.TrimSpace(t))] {
			return SafetyMutating
		}
	}
	return SafetyReadOnly
}

// Entry adalah satu baris katalog: metadata seragam untuk satu template/payload,
// apa pun engine asalnya (BH-SPEC-PAYLOAD §Metadata katalog). Body native template
// TIDAK disalin ke sini — hanya ditunjuk lewat NativeRef.
type Entry struct {
	// TemplateID: id stabil unik di seluruh bank, "<engine>:<native-id>"
	// (mis. "nuclei:prometheus-metrics"). Terbawa ke source_template temuan.
	TemplateID string `json:"template_id"`
	// Source: id sumber asal (mis. "nuclei-official", "custom").
	Source string `json:"source"`
	// Engine: engine yang menjalankan (mis. "nuclei", "custom").
	Engine string `json:"engine"`
	// NativeRef: lokasi template dalam format native-nya di sumber (path relatif).
	NativeRef string `json:"native_ref"`
	// Name: nama ringkas yang terbaca manusia.
	Name string `json:"name"`
	// Type: jenis kerentanan, selaras taksonomi `type` di skema temuan.
	Type string `json:"type,omitempty"`
	// SeverityDefault: severity bawaan (enum skema temuan).
	SeverityDefault finding.Severity `json:"severity_default,omitempty"`
	// Tags: label untuk seleksi (mis. "ssrf", "cve", "fast").
	Tags []string `json:"tags,omitempty"`
	// Safety: klasifikasi dampak payload (read-only | mutating). Diturunkan dari
	// tag, dapat ditimpa sidecar. Engine DAST hanya kirim yang read-only default.
	Safety Safety `json:"safety,omitempty"`
	// References: tautan referensi.
	References []string `json:"references,omitempty"`
	// Trust: diwarisi dari sumber; menentukan perlakuan keamanan.
	Trust Trust `json:"trust"`
	// Version: versi isi template (hash isi), agar perubahan terdeteksi.
	Version string `json:"version"`
	// Enabled: apakah ikut dijalankan secara default. Hanya true bila sumber
	// `trusted` DAN metadata minimum lengkap (lihat canEnable).
	Enabled bool `json:"enabled"`
	// AddedAt: waktu masuk katalog (diisi saat build).
	AddedAt time.Time `json:"added_at,omitempty"`
	// Note: catatan bila metadata tak lengkap / template perlu dilengkapi.
	// Template tetap masuk katalog tapi tidak diam-diam dipakai dengan metadata
	// kosong (BH-SPEC-PAYLOAD §Format satu template).
	Note string `json:"note,omitempty"`
}

// hasMinMeta melaporkan apakah metadata minimum untuk boleh `enabled` terpenuhi:
// nama ada, severity sah, dan type ada (BH-SPEC-PAYLOAD §Pertanyaan terbuka:
// metadata minimum). Tanpa ini, template tetap dikatalogkan tapi nonaktif.
func (e Entry) hasMinMeta() bool {
	return strings.TrimSpace(e.Name) != "" &&
		e.SeverityDefault.Valid() &&
		strings.TrimSpace(e.Type) != ""
}

// canEnable menerapkan aturan keamanan: hanya sumber `trusted` dengan metadata
// minimum lengkap yang boleh aktif otomatis.
func (e Entry) canEnable() bool {
	return e.Trust == TrustTrusted && e.hasMinMeta()
}

// SourceInfo meringkas satu sumber setelah di-scan (untuk panel sumber di UI dan
// ketertelusuran). Version adalah versi sumber bila diketahui (mis. versi
// nuclei-templates), bukan versi tiap template.
type SourceInfo struct {
	ID        string    `json:"id"`
	Engine    string    `json:"engine"`
	Kind      string    `json:"kind"`
	Path      string    `json:"path"`
	Trust     Trust     `json:"trust"`
	Version   string    `json:"version,omitempty"`
	Count     int       `json:"count"`
	Enabled   int       `json:"enabled"`
	Available bool      `json:"available"`
	UpdatedAt time.Time `json:"updated_at"`
	Note      string    `json:"note,omitempty"`
}

// Catalog adalah snapshot bank: semua entri + ringkasan sumber + waktu build.
type Catalog struct {
	Entries []Entry      `json:"entries"`
	Sources []SourceInfo `json:"sources"`
	BuiltAt time.Time    `json:"built_at"`
}

// normSeverity memetakan severity native (string) ke enum skema temuan. Nilai
// tak dikenal/kosong → info (aman), dan known=false agar pemanggil tahu metadata
// severity tak eksplisit.
func normSeverity(s string) (sev finding.Severity, known bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return finding.SeverityCritical, true
	case "high":
		return finding.SeverityHigh, true
	case "medium":
		return finding.SeverityMedium, true
	case "low":
		return finding.SeverityLow, true
	case "info", "informational", "unknown":
		return finding.SeverityInfo, true
	default:
		return finding.SeverityInfo, false
	}
}
