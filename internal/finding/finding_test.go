package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// validFinding mengembalikan temuan minimal yang sah untuk dijadikan dasar uji.
func validFinding() *Finding {
	f := &Finding{
		ID:           "f1a2b3c4-5d6e-7f80-9a1b-2c3d4e5f6071",
		Program:      "acme-public",
		RunID:        "run_20261021_0912",
		Target:       "https://api.acme.io",
		Type:         "ssrf",
		Title:        "SSRF pada parameter url di /fetch",
		Severity:     SeverityCritical,
		Confidence:   ConfidenceMedium,
		Status:       StatusNew,
		SourceEngine: "nuclei",
		Location:     Location{URL: "https://api.acme.io/fetch", Parameter: "url", ParamLocation: ParamBody},
	}
	if err := f.Finalize(time.Date(2026, 10, 21, 9, 14, 3, 0, time.UTC)); err != nil {
		panic(err)
	}
	return f
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestComputeDedupKey_CanonicalForm(t *testing.T) {
	// type di-lowercase, host diambil dari target, path tanpa query, parameter apa adanya.
	got := ComputeDedupKey("SSRF", "https://api.acme.io", "https://api.acme.io/fetch?x=1", "url")
	want := sha256Hex("ssrf|api.acme.io|/fetch|url")
	if got != want {
		t.Fatalf("dedup_key canonical salah\n got=%s\nwant=%s", got, want)
	}
}

func TestComputeDedupKey_StableAcrossRunEngineQuery(t *testing.T) {
	a := ComputeDedupKey("xss", "https://acme.io", "https://acme.io/search?q=1", "q")
	b := ComputeDedupKey("xss", "https://acme.io", "https://acme.io/search?q=9999&z=2", "q")
	if a != b {
		t.Fatalf("nilai query seharusnya tidak memengaruhi dedup_key: %s != %s", a, b)
	}
}

func TestComputeDedupKey_HostCaseInsensitive(t *testing.T) {
	a := ComputeDedupKey("xss", "https://ACME.io", "https://ACME.io/x", "p")
	b := ComputeDedupKey("xss", "https://acme.io", "https://acme.io/x", "p")
	if a != b {
		t.Fatalf("host seharusnya case-insensitive: %s != %s", a, b)
	}
}

func TestComputeDedupKey_TypeCaseInsensitive(t *testing.T) {
	if ComputeDedupKey("XSS", "https://acme.io", "https://acme.io/x", "p") !=
		ComputeDedupKey("xss", "https://acme.io", "https://acme.io/x", "p") {
		t.Fatal("type seharusnya di-lowercase sebelum hashing")
	}
}

func TestComputeDedupKey_DiffersByTypePathParam(t *testing.T) {
	base := ComputeDedupKey("ssrf", "https://acme.io", "https://acme.io/a", "p")
	cases := map[string]string{
		"type beda":  ComputeDedupKey("xss", "https://acme.io", "https://acme.io/a", "p"),
		"path beda":  ComputeDedupKey("ssrf", "https://acme.io", "https://acme.io/b", "p"),
		"param beda": ComputeDedupKey("ssrf", "https://acme.io", "https://acme.io/a", "q"),
		"host beda":  ComputeDedupKey("ssrf", "https://other.io", "https://other.io/a", "p"),
	}
	for name, got := range cases {
		if got == base {
			t.Errorf("%s: dedup_key seharusnya berbeda dari base", name)
		}
	}
}

// Tipe site-wide (header policy, CORS) mengabaikan path: instance per-URL dari
// satu origin terkolaps jadi satu dedup_key.
func TestComputeDedupKey_SiteWideIgnoresPath(t *testing.T) {
	siteWide := []string{
		"content-security-policy-csp-header-not-set",
		"cross-domain-misconfiguration",
		"strict-transport-security-header-not-set",
		"x-content-type-options-header-missing",
	}
	for _, typ := range siteWide {
		a := ComputeDedupKey(typ, "https://acme.io", "https://acme.io/", "")
		b := ComputeDedupKey(typ, "https://acme.io", "https://acme.io/ftp/quarantine", "")
		c := ComputeDedupKey(typ, "https://acme.io", "https://acme.io/sitemap.xml", "")
		if a != b || a != c {
			t.Errorf("%s: path berbeda pada origin sama harus satu dedup_key; %s/%s/%s", typ, a[:8], b[:8], c[:8])
		}
		// Origin berbeda tetap terpisah.
		if other := ComputeDedupKey(typ, "https://other.io", "https://other.io/", ""); other == a {
			t.Errorf("%s: origin berbeda tak boleh terkolaps", typ)
		}
	}
	// Non-site-wide tetap sensitif-path (jaring pengaman regresi).
	if x := ComputeDedupKey("exposed-path", "https://acme.io", "https://acme.io/a", ""); x ==
		ComputeDedupKey("exposed-path", "https://acme.io", "https://acme.io/b", "") {
		t.Error("exposed-path harus tetap membedakan path")
	}
}

func TestFinalize_SetsDerivedFields(t *testing.T) {
	f := &Finding{
		ID:           "id-1",
		Program:      "p",
		RunID:        "r",
		Target:       "https://acme.io",
		Type:         "ssrf",
		Title:        "t",
		Severity:     SeverityHigh,
		Confidence:   ConfidenceMedium,
		Status:       StatusNew,
		SourceEngine: "nuclei",
		Location:     Location{URL: "https://acme.io/fetch", Parameter: "url"},
	}
	if err := f.Finalize(time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("Finalize error: %v", err)
	}
	if f.SchemaVersion != CurrentSchemaVersion {
		t.Errorf("schema_version=%q, want %q", f.SchemaVersion, CurrentSchemaVersion)
	}
	if f.CreatedAt.IsZero() {
		t.Error("created_at seharusnya terisi")
	}
	want := ComputeDedupKey("ssrf", "https://acme.io", "https://acme.io/fetch", "url")
	if f.DedupKey != want {
		t.Errorf("dedup_key=%q, want %q", f.DedupKey, want)
	}
}

func TestFinalize_DoesNotOverrideExisting(t *testing.T) {
	f := validFinding()
	f.DedupKey = "sudah-diset"
	f.SchemaVersion = "9.9"
	orig := f.CreatedAt
	if err := f.Finalize(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("Finalize error: %v", err)
	}
	if f.DedupKey != "sudah-diset" {
		t.Error("Finalize tidak boleh menimpa dedup_key yang sudah diisi")
	}
	if f.SchemaVersion != "9.9" {
		t.Error("Finalize tidak boleh menimpa schema_version yang sudah diisi")
	}
	if !f.CreatedAt.Time.Equal(orig.Time) {
		t.Error("Finalize tidak boleh menimpa created_at yang sudah diisi")
	}
}

func TestValidate_MissingRequired(t *testing.T) {
	err := (&Finding{}).Validate()
	if err == nil {
		t.Fatal("Finding kosong harus gagal validasi")
	}
	for _, field := range []string{"id", "program", "target", "type", "title", "source_engine", "location.url", "created_at"} {
		if !strings.Contains(err.Error(), field) {
			t.Errorf("pesan error harus menyebut %q; dapat: %v", field, err)
		}
	}
}

func TestValidate_BadEnums(t *testing.T) {
	tests := map[string]func(*Finding){
		"severity":       func(f *Finding) { f.Severity = "huge" },
		"confidence":     func(f *Finding) { f.Confidence = "sangat" },
		"status":         func(f *Finding) { f.Status = "open" },
		"param_location": func(f *Finding) { f.Location.ParamLocation = "frag" },
	}
	for name, mutate := range tests {
		f := validFinding()
		mutate(f)
		if err := f.Validate(); err == nil {
			t.Errorf("%s tidak sah seharusnya ditolak", name)
		}
	}
}

func TestValidate_DuplicateRequiresDuplicateOf(t *testing.T) {
	f := validFinding()
	f.Status = StatusDuplicate
	if err := f.Validate(); err == nil {
		t.Fatal("status=duplicate tanpa duplicate_of harus ditolak")
	}
	f.DuplicateOf = f.ID
	if err := f.Validate(); err != nil {
		t.Fatalf("status=duplicate dengan duplicate_of harus lolos: %v", err)
	}
}

func TestJSON_TimeFormatAndOmitEmpty(t *testing.T) {
	f := validFinding()
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	s := string(b)

	if !strings.Contains(s, `"created_at":"2026-10-21T09:14:03Z"`) {
		t.Errorf("created_at harus UTC ISO 8601 presisi detik; dapat: %s", s)
	}
	// Field opsional yang kosong harus hilang dari JSON (bukan null).
	for _, k := range []string{"description", "cvss", "cwe", "tags", "evidence",
		"reproduction", "source_template", "references", "raw", "duplicate_of",
		"in_report", "verified_by", "updated_at"} {
		if strings.Contains(s, `"`+k+`"`) {
			t.Errorf("field opsional kosong %q seharusnya dihilangkan; dapat: %s", k, s)
		}
	}
}

func TestJSON_RoundTrip(t *testing.T) {
	f := validFinding()
	f.Evidence = &Evidence{
		Request: "POST /fetch HTTP/1.1\nHost: api.acme.io\nAuthorization: [REDACTED]\n",
		Payload: "http://169.254.169.254/latest/meta-data/",
		Matched: "ami-id",
	}
	f.CWE = []string{"CWE-918"}
	upd := NewTime(time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC))
	f.UpdatedAt = &upd

	b, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	var g Finding
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	if g.DedupKey != f.DedupKey || g.Type != f.Type || g.Severity != f.Severity {
		t.Error("field inti berubah setelah round-trip")
	}
	if !g.CreatedAt.Time.Equal(f.CreatedAt.Time) {
		t.Errorf("created_at berubah: %v != %v", g.CreatedAt.Time, f.CreatedAt.Time)
	}
	if g.UpdatedAt == nil || !g.UpdatedAt.Time.Equal(upd.Time) {
		t.Error("updated_at tidak bertahan round-trip")
	}
	if g.Evidence == nil || g.Evidence.Matched != "ami-id" {
		t.Error("evidence tidak bertahan round-trip")
	}
}
