// Package finding mendefinisikan Skema Temuan Seragam (BH-SPEC-FINDING):
// satu format tunggal tempat semua engine (recon & DAST) menormalkan hasilnya,
// sekaligus sumber data untuk triase dan report.
//
// Paket ini sengaja tanpa dependency eksternal: ia fondasi yang dirujuk store,
// triase, report, dan engine adapter, jadi harus stabil dan ringan.
package finding

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// CurrentSchemaVersion adalah versi skema yang ditulis komponen saat ini.
// Kenaikan versi mengikuti aturan MAYOR.MINOR di BH-SPEC-FINDING.
const CurrentSchemaVersion = "1.0"

// Severity: tingkat keparahan temuan. Enum tertutup (BH-SPEC-FINDING).
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Valid melaporkan apakah s salah satu nilai severity yang sah.
func (s Severity) Valid() bool {
	switch s {
	case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	}
	return false
}

// Confidence: keyakinan otomatis sebelum verifikasi manual. Enum tertutup.
type Confidence string

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

// Valid melaporkan apakah c salah satu nilai confidence yang sah.
func (c Confidence) Valid() bool {
	switch c {
	case ConfidenceLow, ConfidenceMedium, ConfidenceHigh:
		return true
	}
	return false
}

// Status: status triase temuan. Enum tertutup (BH-SPEC-FINDING).
type Status string

const (
	StatusNew           Status = "new"
	StatusConfirmed     Status = "confirmed"
	StatusDuplicate     Status = "duplicate"
	StatusFalsePositive Status = "false_positive"
	StatusIgnored       Status = "ignored"
)

// Valid melaporkan apakah s salah satu nilai status yang sah.
func (s Status) Valid() bool {
	switch s {
	case StatusNew, StatusConfirmed, StatusDuplicate, StatusFalsePositive, StatusIgnored:
		return true
	}
	return false
}

// ParamLocation: lokasi parameter titik masuk. Opsional; divalidasi bila diisi.
type ParamLocation string

const (
	ParamQuery  ParamLocation = "query"
	ParamBody   ParamLocation = "body"
	ParamHeader ParamLocation = "header"
	ParamCookie ParamLocation = "cookie"
	ParamPath   ParamLocation = "path"
)

// Valid melaporkan apakah p salah satu lokasi parameter yang sah.
func (p ParamLocation) Valid() bool {
	switch p {
	case ParamQuery, ParamBody, ParamHeader, ParamCookie, ParamPath:
		return true
	}
	return false
}

// timeLayout: UTC ISO 8601 presisi detik, mis. "2026-10-21T09:14:03Z".
const timeLayout = "2006-01-02T15:04:05Z07:00"

// Time adalah timestamp yang selalu diserialisasi sebagai UTC ISO 8601 presisi
// detik, sesuai prinsip "Waktu dalam UTC ISO 8601" di BH-SPEC-FINDING.
type Time struct{ time.Time }

// NewTime menormalkan t ke UTC presisi detik.
func NewTime(t time.Time) Time { return Time{t.UTC().Truncate(time.Second)} }

// MarshalJSON menulis waktu sebagai string UTC ISO 8601 presisi detik.
func (t Time) MarshalJSON() ([]byte, error) {
	return []byte(`"` + t.UTC().Truncate(time.Second).Format(timeLayout) + `"`), nil
}

// UnmarshalJSON membaca string UTC ISO 8601; string kosong/null jadi waktu nol.
func (t *Time) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		t.Time = time.Time{}
		return nil
	}
	parsed, err := time.Parse(timeLayout, s)
	if err != nil {
		return fmt.Errorf("finding: waktu tidak valid %q: %w", s, err)
	}
	t.Time = parsed.UTC()
	return nil
}

// CVSS membawa skor CVSS opsional bila engine/template menyediakannya.
type CVSS struct {
	Version string  `json:"version,omitempty"`
	Vector  string  `json:"vector,omitempty"`
	Score   float64 `json:"score,omitempty"`
}

// Location menunjuk di mana persisnya temuan berada. Hanya URL yang wajib.
type Location struct {
	URL           string        `json:"url"`
	Method        string        `json:"method,omitempty"`
	Parameter     string        `json:"parameter,omitempty"`
	ParamLocation ParamLocation `json:"param_location,omitempty"`
}

// Evidence menyimpan bukti yang SUDAH dibersihkan dari secret. Semua sub-field
// opsional, tapi minimal satu sebaiknya ada agar temuan bisa diverifikasi.
// Penyensoran secret adalah tanggung jawab adapter sebelum mengisi struct ini
// (BH-SPEC-FINDING: skema tidak pernah menyimpan secret mentah).
type Evidence struct {
	Request         string `json:"request,omitempty"`
	ResponseExcerpt string `json:"response_excerpt,omitempty"`
	Payload         string `json:"payload,omitempty"`
	Matched         string `json:"matched,omitempty"`
	ScreenshotRef   string `json:"screenshot_ref,omitempty"`
}

// Finding adalah satu catatan ternormalisasi: satu isu keamanan pada satu
// lokasi, dalam bentuk yang sama apa pun engine asalnya.
//
// Field opsional memakai omitempty sehingga dihilangkan dari JSON saat kosong,
// bukan ditulis null (BH-SPEC-FINDING).
type Finding struct {
	SchemaVersion string `json:"schema_version"`
	ID            string `json:"id"`
	DedupKey      string `json:"dedup_key"`
	Program       string `json:"program"`
	RunID         string `json:"run_id"`
	Target        string `json:"target"`
	Type          string `json:"type"`
	Title         string `json:"title"`
	Description   string `json:"description,omitempty"`

	Severity   Severity   `json:"severity"`
	Confidence Confidence `json:"confidence"`
	CVSS       *CVSS      `json:"cvss,omitempty"`
	CWE        []string   `json:"cwe,omitempty"`
	Tags       []string   `json:"tags,omitempty"`

	Location     Location  `json:"location"`
	Evidence     *Evidence `json:"evidence,omitempty"`
	Reproduction []string  `json:"reproduction,omitempty"`

	SourceEngine   string          `json:"source_engine"`
	SourceTemplate string          `json:"source_template,omitempty"`
	References     []string        `json:"references,omitempty"`
	Raw            json.RawMessage `json:"raw,omitempty"`

	Status      Status `json:"status"`
	DuplicateOf string `json:"duplicate_of,omitempty"`
	InReport    bool   `json:"in_report,omitempty"`
	VerifiedBy  string `json:"verified_by,omitempty"`

	CreatedAt Time  `json:"created_at"`
	UpdatedAt *Time `json:"updated_at,omitempty"`
}

// Finalize mengisi field turunan yang belum terisi (schema_version, created_at,
// dedup_key) lalu memvalidasi. Adapter engine memanggil ini setelah memetakan
// output mentah ke skema. ID tetap tanggung jawab pemanggil (UUID dari store).
func (f *Finding) Finalize(now time.Time) error {
	if f.SchemaVersion == "" {
		f.SchemaVersion = CurrentSchemaVersion
	}
	if f.CreatedAt.IsZero() {
		f.CreatedAt = NewTime(now)
	}
	if f.DedupKey == "" {
		f.DedupKey = ComputeDedupKey(f.Type, f.Target, f.Location.URL, f.Location.Parameter)
	}
	return f.Validate()
}

// Validate memastikan semua field wajib terisi dan setiap enum sah. Store
// memakai ini sebagai penjaga sebelum menyimpan.
func (f *Finding) Validate() error {
	required := map[string]string{
		"schema_version": f.SchemaVersion,
		"id":             f.ID,
		"dedup_key":      f.DedupKey,
		"program":        f.Program,
		"run_id":         f.RunID,
		"target":         f.Target,
		"type":           f.Type,
		"title":          f.Title,
		"source_engine":  f.SourceEngine,
	}
	var missing []string
	for name, val := range required {
		if strings.TrimSpace(val) == "" {
			missing = append(missing, name)
		}
	}
	if strings.TrimSpace(f.Location.URL) == "" {
		missing = append(missing, "location.url")
	}
	if f.CreatedAt.IsZero() {
		missing = append(missing, "created_at")
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("finding: field wajib kosong: %s", strings.Join(missing, ", "))
	}

	if !f.Severity.Valid() {
		return fmt.Errorf("finding: severity tidak sah: %q", f.Severity)
	}
	if !f.Confidence.Valid() {
		return fmt.Errorf("finding: confidence tidak sah: %q", f.Confidence)
	}
	if !f.Status.Valid() {
		return fmt.Errorf("finding: status tidak sah: %q", f.Status)
	}
	if f.Location.ParamLocation != "" && !f.Location.ParamLocation.Valid() {
		return fmt.Errorf("finding: param_location tidak sah: %q", f.Location.ParamLocation)
	}
	if f.Status == StatusDuplicate && strings.TrimSpace(f.DuplicateOf) == "" {
		return fmt.Errorf("finding: status=duplicate wajib mengisi duplicate_of")
	}
	return nil
}
