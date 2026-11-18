package sast

import (
	"slices"
	"strings"
	"testing"

	"bughound/internal/finding"
)

// gitleaks SARIF with a secret that is NOT redacted yet. It tests the
// redactSecret safety net (in case gitleaks' --redact fails or is missing). The
// "secret" value below is synthetic and deliberately matches NO provider's
// format (to avoid push protection scanners); only the length of the run is
// tested, not the shape of the key.
const gitleaksRawSARIF = `{
  "runs": [{
    "tool": {"driver": {"name": "gitleaks", "rules": [
      {"id": "generic-api-key", "name": "Generic API Key", "shortDescription": {"text": "Generic API Key detected"}}
    ]}},
    "results": [
      {"ruleId": "generic-api-key", "level": "error",
       "message": {"text": "generic-api-key has detected a secret"},
       "locations": [{"physicalLocation": {"artifactLocation": {"uri": "config/app.yml"}, "region": {"startLine": 5, "snippet": {"text": "api_key: NOTREAL_ABCD1234EFGH5678IJKL9012MNOP"}}}}]}
    ]
  }]
}`

func TestParseGitleaksRedactsAndEnriches(t *testing.T) {
	fs, err := parseGitleaks([]byte(gitleaksRawSARIF))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("want 1, got %d", len(fs))
	}
	f := fs[0]
	if f.Type != "generic-api-key" {
		t.Errorf("type: %s", f.Type)
	}
	if f.Severity != finding.SeverityHigh { // level error
		t.Errorf("severity: want high, got %s", f.Severity)
	}
	// CWE-798 is the default for a secret.
	if got := strings.Join(f.CWE, ","); got != "CWE-798" {
		t.Errorf("CWE default: want CWE-798, got %q", got)
	}
	// tag secret + sast + gitleaks.
	for _, want := range []string{"secret", "sast", "gitleaks"} {
		if !hasTag(f.Tags, want) {
			t.Errorf("tag %q is missing from %v", want, f.Tags)
		}
	}
	if f.Evidence == nil {
		t.Fatal("the evidence is missing")
	}
	// The secret value must NOT be there; the context (variable name) stays.
	if strings.Contains(f.Evidence.Matched, "ABCD1234EFGH5678IJKL9012MNOP") {
		t.Errorf("SECRET LEAKED: %q", f.Evidence.Matched)
	}
	if !strings.Contains(f.Evidence.Matched, "REDACTED") {
		t.Errorf("not redacted: %q", f.Evidence.Matched)
	}
	if !strings.Contains(f.Evidence.Matched, "api_key") {
		t.Errorf("the context is missing: %q", f.Evidence.Matched)
	}
}

func TestRedactSecret(t *testing.T) {
	cases := []struct {
		in       string
		leakFrag string // a substring that must NOT appear (empty = no check)
		keep     string // a substring that MUST stay
	}{
		{"api_key: NOTREAL_ABCD1234EFGH5678IJKL9012MNOP", "ABCD1234EFGH5678IJKL9012MNOP", "api_key"},
		{"AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE", ""}, // 20 char → mask
		{"id = 42", "", "id = 42"},             // short → intact
		{"name: build-server-01", "", "name:"}, // a short token stays intact
	}
	for _, c := range cases {
		got := redactSecret(c.in)
		if c.leakFrag != "" && strings.Contains(got, c.leakFrag) {
			t.Errorf("redactSecret(%q)=%q still leaks %q", c.in, got, c.leakFrag)
		}
		if c.keep != "" && !strings.Contains(got, c.keep) {
			t.Errorf("redactSecret(%q)=%q lost the context %q", c.in, got, c.keep)
		}
	}
}

func TestGitleaksRegistered(t *testing.T) {
	if _, ok := Lookup("gitleaks"); !ok {
		t.Error("the gitleaks adapter is not registered")
	}
}

func hasTag(tags []string, t string) bool {
	return slices.Contains(tags, t)
}
