package sast

import (
	"slices"
	"strings"
	"testing"

	"bughound/internal/finding"
)

// gitleaks SARIF dengan secret BELUM diredaksi — menguji jaring pengaman
// redactSecret (seandainya --redact gitleaks gagal/absen). Nilai "secret" di
// bawah sintetis dan sengaja BUKAN format provider mana pun (hindari push
// protection scanner); yang diuji hanya panjang deret, bukan bentuk kuncinya.
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
		t.Fatalf("mau 1, dapat %d", len(fs))
	}
	f := fs[0]
	if f.Type != "generic-api-key" {
		t.Errorf("type: %s", f.Type)
	}
	if f.Severity != finding.SeverityHigh { // level error
		t.Errorf("severity: mau high, dapat %s", f.Severity)
	}
	// CWE-798 default utk secret.
	if got := strings.Join(f.CWE, ","); got != "CWE-798" {
		t.Errorf("CWE default: mau CWE-798, dapat %q", got)
	}
	// tag secret + sast + gitleaks.
	for _, want := range []string{"secret", "sast", "gitleaks"} {
		if !hasTag(f.Tags, want) {
			t.Errorf("tag %q hilang dari %v", want, f.Tags)
		}
	}
	if f.Evidence == nil {
		t.Fatal("evidence hilang")
	}
	// Nilai secret TAK boleh ada; konteks (nama variabel) tetap.
	if strings.Contains(f.Evidence.Matched, "ABCD1234EFGH5678IJKL9012MNOP") {
		t.Errorf("SECRET BOCOR: %q", f.Evidence.Matched)
	}
	if !strings.Contains(f.Evidence.Matched, "REDACTED") {
		t.Errorf("tak teredaksi: %q", f.Evidence.Matched)
	}
	if !strings.Contains(f.Evidence.Matched, "api_key") {
		t.Errorf("konteks hilang: %q", f.Evidence.Matched)
	}
}

func TestRedactSecret(t *testing.T) {
	cases := []struct {
		in       string
		leakFrag string // substring yang TAK boleh muncul (kosong = tak cek)
		keep     string // substring yang HARUS tetap
	}{
		{"api_key: NOTREAL_ABCD1234EFGH5678IJKL9012MNOP", "ABCD1234EFGH5678IJKL9012MNOP", "api_key"},
		{"AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE", ""}, // 20 char → mask
		{"id = 42", "", "id = 42"},             // pendek → utuh
		{"name: build-server-01", "", "name:"}, // token pendek utuh
	}
	for _, c := range cases {
		got := redactSecret(c.in)
		if c.leakFrag != "" && strings.Contains(got, c.leakFrag) {
			t.Errorf("redactSecret(%q)=%q masih bocor %q", c.in, got, c.leakFrag)
		}
		if c.keep != "" && !strings.Contains(got, c.keep) {
			t.Errorf("redactSecret(%q)=%q kehilangan konteks %q", c.in, got, c.keep)
		}
	}
}

func TestGitleaksRegistered(t *testing.T) {
	if _, ok := Lookup("gitleaks"); !ok {
		t.Error("adapter gitleaks tak terdaftar")
	}
}

func hasTag(tags []string, t string) bool {
	return slices.Contains(tags, t)
}
