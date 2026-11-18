package nuclei

import (
	"strings"
	"testing"
	"time"

	"bughound/internal/finding"
)

func TestParseSample(t *testing.T) {
	fs, err := Parse(strings.NewReader(string(sampleJSONL)), "demo", "run1")
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(fs) != 2 {
		t.Fatalf("want 2 findings, got %d", len(fs))
	}

	ssrf := fs[0]
	if ssrf.Type != "ssrf-via-fetch" {
		t.Errorf("type=%q", ssrf.Type)
	}
	if ssrf.Severity != finding.SeverityCritical {
		t.Errorf("severity=%q", ssrf.Severity)
	}
	if ssrf.Title != "SSRF via fetch parameter" {
		t.Errorf("title=%q", ssrf.Title)
	}
	if ssrf.Confidence != finding.ConfidenceHigh {
		t.Errorf("confidence=%q (matcher-status true => high)", ssrf.Confidence)
	}
	if len(ssrf.CWE) != 1 || ssrf.CWE[0] != "CWE-918" {
		t.Errorf("cwe=%v", ssrf.CWE)
	}
	if ssrf.CVSS == nil || ssrf.CVSS.Score != 9.3 || ssrf.CVSS.Version != "3.1" {
		t.Errorf("cvss=%+v", ssrf.CVSS)
	}
	if ssrf.SourceEngine != "nuclei" || ssrf.SourceTemplate != "ssrf-via-fetch" {
		t.Errorf("source=%s/%s", ssrf.SourceEngine, ssrf.SourceTemplate)
	}
	if ssrf.Location.URL != "https://demo.test/fetch" {
		t.Errorf("location.url=%q", ssrf.Location.URL)
	}
	if ssrf.CreatedAt.IsZero() {
		t.Error("created_at must be taken from the nuclei timestamp")
	}

	// Once the id is assigned (normally by the store), the finding must be valid.
	ssrf.ID = "11111111-1111-4111-8111-111111111111"
	if err := ssrf.Finalize(time.Now()); err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	if ssrf.DedupKey == "" {
		t.Error("dedup_key is empty after Finalize")
	}
}

func TestParseSanitizesSecrets(t *testing.T) {
	fs, err := Parse(strings.NewReader(string(sampleJSONL)), "demo", "r")
	if err != nil {
		t.Fatal(err)
	}
	ssrf := fs[0]
	if ssrf.Evidence == nil {
		t.Fatal("evidence nil")
	}
	req := ssrf.Evidence.Request
	if !strings.Contains(req, redacted) {
		t.Error("evidence.request must contain [REDACTED]")
	}
	for _, secret := range []string{"SECRET-abc123", "deadbeef"} {
		if strings.Contains(req, secret) {
			t.Errorf("evidence.request leaks the secret %q", secret)
		}
		if strings.Contains(string(ssrf.Raw), secret) {
			t.Errorf("raw leaks the secret %q", secret)
		}
	}
	if !strings.Contains(req, "Host: demo.test") {
		t.Error("a non-sensitive header should be kept")
	}
}

func TestSanitizeHTTP(t *testing.T) {
	in := "GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer abc\r\nCookie: s=1\r\nAccept: */*\r\n"
	out := sanitizeHTTP(in)
	if strings.Contains(out, "Bearer abc") || strings.Contains(out, "s=1") {
		t.Error("a sensitive value was not redacted")
	}
	if !strings.Contains(out, "Host: x") || !strings.Contains(out, "Accept: */*") {
		t.Error("an ordinary header must not change")
	}
	if !strings.Contains(out, "Authorization: "+redacted) {
		t.Error("Authorization must become [REDACTED]")
	}
}

func TestStringListFlexible(t *testing.T) {
	// tags as a single string "a, b"; reference as an array.
	line := `{"template-id":"t","host":"https://demo.test","matched-at":"https://demo.test/x",` +
		`"info":{"name":"n","severity":"low","tags":"a, b","reference":["https://e"]}}`
	fs, err := Parse(strings.NewReader(line), "p", "r")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 {
		t.Fatalf("got %d findings", len(fs))
	}
	if len(fs[0].Tags) != 2 || fs[0].Tags[0] != "a" || fs[0].Tags[1] != "b" {
		t.Errorf("the tags string failed to parse into a slice: %v", fs[0].Tags)
	}
}

func TestParseSkipsBannerAndBlank(t *testing.T) {
	in := "[INF] nuclei banner line\n\n" +
		`{"template-id":"t","host":"https://demo.test","matched-at":"https://demo.test/x","info":{"severity":"info"}}` + "\n"
	fs, err := Parse(strings.NewReader(in), "p", "r")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("banners & blank lines must be skipped, got %d", len(fs))
	}
}

func TestParseMalformedJSONErrors(t *testing.T) {
	if _, err := Parse(strings.NewReader(`{"template-id":"t",`), "p", "r"); err == nil {
		t.Fatal("a broken JSON line must produce an error")
	}
}
