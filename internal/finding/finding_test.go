package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// validFinding returns a minimal valid finding to base tests on.
func validFinding() *Finding {
	f := &Finding{
		ID:           "f1a2b3c4-5d6e-7f80-9a1b-2c3d4e5f6071",
		Program:      "acme-public",
		RunID:        "run_20261021_0912",
		Target:       "https://api.acme.io",
		Type:         "ssrf",
		Title:        "SSRF in the url parameter at /fetch",
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
	// type is lowercased, the host comes from target, the path has no query, then
	// the method (empty here) and the parameter as is.
	got := ComputeDedupKey("SSRF", "https://api.acme.io", "https://api.acme.io/fetch?x=1", "", "url")
	want := sha256Hex("ssrf|api.acme.io|/fetch||url")
	if got != want {
		t.Fatalf("wrong canonical dedup_key\n got=%s\nwant=%s", got, want)
	}
}

func TestComputeDedupKey_StableAcrossRunEngineQuery(t *testing.T) {
	a := ComputeDedupKey("xss", "https://acme.io", "https://acme.io/search?q=1", "GET", "q")
	b := ComputeDedupKey("xss", "https://acme.io", "https://acme.io/search?q=9999&z=2", "GET", "q")
	if a != b {
		t.Fatalf("query values should not affect dedup_key: %s != %s", a, b)
	}
}

func TestComputeDedupKey_HostCaseInsensitive(t *testing.T) {
	a := ComputeDedupKey("xss", "https://ACME.io", "https://ACME.io/x", "", "p")
	b := ComputeDedupKey("xss", "https://acme.io", "https://acme.io/x", "", "p")
	if a != b {
		t.Fatalf("the host should be case-insensitive: %s != %s", a, b)
	}
}

func TestComputeDedupKey_TypeCaseInsensitive(t *testing.T) {
	if ComputeDedupKey("XSS", "https://acme.io", "https://acme.io/x", "", "p") !=
		ComputeDedupKey("xss", "https://acme.io", "https://acme.io/x", "", "p") {
		t.Fatal("type should be lowercased before hashing")
	}
}

func TestComputeDedupKey_MethodCaseInsensitive(t *testing.T) {
	if ComputeDedupKey("xss", "https://acme.io", "https://acme.io/x", "post", "p") !=
		ComputeDedupKey("xss", "https://acme.io", "https://acme.io/x", "POST", "p") {
		t.Fatal("method should be upper-cased before hashing")
	}
}

func TestComputeDedupKey_DiffersByTypePathParamMethod(t *testing.T) {
	base := ComputeDedupKey("ssrf", "https://acme.io", "https://acme.io/a", "GET", "p")
	cases := map[string]string{
		"type differs":   ComputeDedupKey("xss", "https://acme.io", "https://acme.io/a", "GET", "p"),
		"path differs":   ComputeDedupKey("ssrf", "https://acme.io", "https://acme.io/b", "GET", "p"),
		"param differs":  ComputeDedupKey("ssrf", "https://acme.io", "https://acme.io/a", "GET", "q"),
		"method differs": ComputeDedupKey("ssrf", "https://acme.io", "https://acme.io/a", "POST", "p"),
		"host differs":   ComputeDedupKey("ssrf", "https://other.io", "https://other.io/a", "GET", "p"),
	}
	for name, got := range cases {
		if got == base {
			t.Errorf("%s: dedup_key should differ from base", name)
		}
	}
}

// Site-wide types (header policy, CORS) ignore the path AND the method:
// per-URL/method instances from one origin collapse into one dedup_key.
func TestComputeDedupKey_SiteWideIgnoresPathAndMethod(t *testing.T) {
	siteWide := []string{
		"content-security-policy-csp-header-not-set",
		"cross-domain-misconfiguration",
		"strict-transport-security-header-not-set",
		"x-content-type-options-header-missing",
	}
	for _, typ := range siteWide {
		a := ComputeDedupKey(typ, "https://acme.io", "https://acme.io/", "GET", "")
		b := ComputeDedupKey(typ, "https://acme.io", "https://acme.io/ftp/quarantine", "POST", "")
		c := ComputeDedupKey(typ, "https://acme.io", "https://acme.io/sitemap.xml", "", "")
		if a != b || a != c {
			t.Errorf("%s: different paths/methods on the same origin must share one dedup_key; %s/%s/%s", typ, a[:8], b[:8], c[:8])
		}
		// A different origin stays separate.
		if other := ComputeDedupKey(typ, "https://other.io", "https://other.io/", "GET", ""); other == a {
			t.Errorf("%s: a different origin must not collapse", typ)
		}
	}
	// Non-site-wide types stay path-sensitive (a regression safety net).
	if x := ComputeDedupKey("exposed-path", "https://acme.io", "https://acme.io/a", "", ""); x ==
		ComputeDedupKey("exposed-path", "https://acme.io", "https://acme.io/b", "", "") {
		t.Error("exposed-path must still tell paths apart")
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
		t.Error("created_at should be set")
	}
	want := ComputeDedupKey("ssrf", "https://acme.io", "https://acme.io/fetch", "", "url")
	if f.DedupKey != want {
		t.Errorf("dedup_key=%q, want %q", f.DedupKey, want)
	}
}

func TestFinalize_DoesNotOverrideExisting(t *testing.T) {
	f := validFinding()
	f.DedupKey = "already-set"
	f.SchemaVersion = "9.9"
	orig := f.CreatedAt
	if err := f.Finalize(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("Finalize error: %v", err)
	}
	if f.DedupKey != "already-set" {
		t.Error("Finalize must not overwrite a dedup_key that is already set")
	}
	if f.SchemaVersion != "9.9" {
		t.Error("Finalize must not overwrite a schema_version that is already set")
	}
	if !f.CreatedAt.Time.Equal(orig.Time) {
		t.Error("Finalize must not overwrite a created_at that is already set")
	}
}

func TestValidate_MissingRequired(t *testing.T) {
	err := (&Finding{}).Validate()
	if err == nil {
		t.Fatal("an empty Finding must fail validation")
	}
	for _, field := range []string{"id", "program", "target", "type", "title", "source_engine", "location.url", "created_at"} {
		if !strings.Contains(err.Error(), field) {
			t.Errorf("the error message must mention %q; got: %v", field, err)
		}
	}
}

func TestValidate_BadEnums(t *testing.T) {
	tests := map[string]func(*Finding){
		"severity":       func(f *Finding) { f.Severity = "huge" },
		"confidence":     func(f *Finding) { f.Confidence = "very" },
		"status":         func(f *Finding) { f.Status = "open" },
		"param_location": func(f *Finding) { f.Location.ParamLocation = "frag" },
	}
	for name, mutate := range tests {
		f := validFinding()
		mutate(f)
		if err := f.Validate(); err == nil {
			t.Errorf("an invalid %s should be rejected", name)
		}
	}
}

func TestValidate_DuplicateRequiresDuplicateOf(t *testing.T) {
	f := validFinding()
	f.Status = StatusDuplicate
	if err := f.Validate(); err == nil {
		t.Fatal("status=duplicate without duplicate_of must be rejected")
	}
	f.DuplicateOf = f.ID
	if err := f.Validate(); err != nil {
		t.Fatalf("status=duplicate with duplicate_of must pass: %v", err)
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
		t.Errorf("created_at must be UTC ISO 8601 with second precision; got: %s", s)
	}
	// Empty optional fields must be absent from the JSON (not null).
	for _, k := range []string{"description", "cvss", "cwe", "tags", "evidence",
		"reproduction", "source_template", "references", "raw", "duplicate_of",
		"in_report", "verified_by", "updated_at"} {
		if strings.Contains(s, `"`+k+`"`) {
			t.Errorf("empty optional field %q should be omitted; got: %s", k, s)
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
		t.Error("core fields changed after the round-trip")
	}
	if !g.CreatedAt.Time.Equal(f.CreatedAt.Time) {
		t.Errorf("created_at changed: %v != %v", g.CreatedAt.Time, f.CreatedAt.Time)
	}
	if g.UpdatedAt == nil || !g.UpdatedAt.Time.Equal(upd.Time) {
		t.Error("updated_at did not survive the round-trip")
	}
	if g.Evidence == nil || g.Evidence.Matched != "ami-id" {
		t.Error("evidence did not survive the round-trip")
	}
}

func TestFinalizeClampsOversizedEvidence(t *testing.T) {
	big := strings.Repeat("A", 40*1024) // > maxEvidenceField (32 KiB)
	f := validFinding()
	f.Evidence = &Evidence{Request: big, ResponseExcerpt: "small", ScreenshotRef: big}
	if err := f.Finalize(time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	if len(f.Evidence.Request) > maxEvidenceField {
		t.Errorf("Request must be truncated to <= %d bytes; got %d", maxEvidenceField, len(f.Evidence.Request))
	}
	if !strings.Contains(f.Evidence.Request, "truncated") {
		t.Error("a truncated field must carry the truncation marker")
	}
	if f.Evidence.ResponseExcerpt != "small" {
		t.Errorf("a short field must not change; got %q", f.Evidence.ResponseExcerpt)
	}
	// ScreenshotRef = a reference (path/URL), not content -> not truncated.
	if len(f.Evidence.ScreenshotRef) != len(big) {
		t.Errorf("ScreenshotRef must not be truncated; got %d bytes", len(f.Evidence.ScreenshotRef))
	}

	// Idempotent: a second Finalize does not truncate again.
	before := f.Evidence.Request
	if err := f.Finalize(time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("second Finalize: %v", err)
	}
	if f.Evidence.Request != before {
		t.Error("clamp must be idempotent; the second call changed the content")
	}
}

func TestClampTextRuneSafe(t *testing.T) {
	// Truncation must not split a multibyte character: the result is still valid
	// UTF-8 and does not exceed the byte limit.
	s := strings.Repeat("é", 20*1024) // 'é' = 2 bytes -> 40 KiB, > the limit
	out := clampText(s, maxEvidenceField)
	if !utf8.ValidString(out) {
		t.Error("the clamp result must be valid UTF-8 (no split rune)")
	}
	if len(out) > maxEvidenceField {
		t.Errorf("the result must be <= %d bytes; got %d", maxEvidenceField, len(out))
	}
}
