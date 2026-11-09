package sast

import (
	"strings"
	"testing"

	"bughound/internal/finding"
)

// codeqlSARIF: gaya CodeQL — rules dengan security-severity numerik + tag
// external/cwe/cwe-###, results menunjuk rule via ruleIndex.
const codeqlSARIF = `{
  "runs": [{
    "tool": {"driver": {"name": "CodeQL", "rules": [
      {"id": "js/sql-injection", "name": "SQL injection",
       "shortDescription": {"text": "Database query built from user-controlled sources"},
       "helpUri": "https://codeql.github.com/sqli",
       "defaultConfiguration": {"level": "error"},
       "properties": {"security-severity": "9.8", "tags": ["security", "external/cwe/cwe-089", "precision/high"]}},
      {"id": "js/weak-rand", "name": "Weak randomness",
       "shortDescription": {"text": "Insecure randomness"},
       "defaultConfiguration": {"level": "warning"},
       "properties": {"security-severity": "5.0", "tags": ["external/cwe/cwe-338"]}}
    ]}},
    "results": [
      {"ruleId": "js/sql-injection", "ruleIndex": 0,
       "message": {"text": "This query depends on a user-provided value."},
       "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/db.js"}, "region": {"startLine": 42, "snippet": {"text": "db.query('SELECT ... ' + req.body.id)"}}}}]},
      {"ruleId": "js/weak-rand", "ruleIndex": 1,
       "message": {"text": "Math.random used for token."},
       "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/token.js"}, "region": {"startLine": 7}}}]}
    ]
  }]
}`

// gitleaksSARIF: gaya gitleaks — level error, cwe sebagai string tunggal, snippet
// berisi rahasia (harus bisa diredaksi).
const gitleaksSARIF = `{
  "runs": [{
    "tool": {"driver": {"name": "gitleaks", "rules": [
      {"id": "aws-access-token", "name": "AWS Access Token",
       "shortDescription": {"text": "AWS Access Token"},
       "properties": {"cwe": "CWE-798"}}
    ]}},
    "results": [
      {"ruleId": "aws-access-token", "level": "error",
       "message": {"text": "aws-access-token has detected secret"},
       "locations": [{"physicalLocation": {"artifactLocation": {"uri": "config/prod.env"}, "region": {"startLine": 3, "snippet": {"text": "AWS_KEY=AKIAIOSFODNN7EXAMPLE"}}}}]}
    ]
  }]
}`

func findByType(fs []*finding.Finding, t string) *finding.Finding {
	for _, f := range fs {
		if f.Type == t {
			return f
		}
	}
	return nil
}

func TestNormalizeSARIFCodeQL(t *testing.T) {
	fs, err := NormalizeSARIF([]byte(codeqlSARIF), "codeql", nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(fs) != 2 {
		t.Fatalf("mau 2 temuan, dapat %d", len(fs))
	}
	sqli := findByType(fs, "js/sql-injection")
	if sqli == nil {
		t.Fatal("temuan sql-injection hilang")
	}
	// security-severity 9.8 → critical (menang atas level error=high).
	if sqli.Severity != finding.SeverityCritical {
		t.Errorf("severity: mau critical, dapat %s", sqli.Severity)
	}
	if sqli.Location.URL != "src/db.js:42" {
		t.Errorf("location: mau src/db.js:42, dapat %s", sqli.Location.URL)
	}
	if sqli.Title != "Database query built from user-controlled sources" {
		t.Errorf("title dari shortDescription salah: %q", sqli.Title)
	}
	if sqli.SourceEngine != "codeql" {
		t.Errorf("source engine: mau codeql, dapat %s", sqli.SourceEngine)
	}
	if got := strings.Join(sqli.CWE, ","); got != "CWE-89" {
		t.Errorf("CWE dari tag external/cwe/cwe-089: mau CWE-89, dapat %q", got)
	}
	// tag teknis (external/cwe/..., precision/...) dibuang dari Tags tampil.
	for _, tag := range sqli.Tags {
		if strings.Contains(tag, "/") {
			t.Errorf("tag teknis bocor ke Tags: %q", tag)
		}
	}
	if sqli.Evidence == nil || !strings.Contains(sqli.Evidence.Matched, "SELECT") {
		t.Errorf("evidence snippet hilang")
	}
	// security-severity 5.0 → medium.
	rand := findByType(fs, "js/weak-rand")
	if rand == nil || rand.Severity != finding.SeverityMedium {
		t.Errorf("weak-rand: mau medium, dapat %v", rand)
	}
	if rand.Evidence != nil {
		t.Errorf("tanpa snippet seharusnya tak ada evidence, dapat %q", rand.Evidence.Matched)
	}
}

func TestNormalizeSARIFGitleaksRedaction(t *testing.T) {
	// redact: ganti nilai setelah '=' dengan mask (simulasi sensor secret).
	redact := func(s string) string {
		if i := strings.IndexByte(s, '='); i >= 0 {
			return s[:i+1] + "***REDACTED***"
		}
		return "***REDACTED***"
	}
	fs, err := NormalizeSARIF([]byte(gitleaksSARIF), "gitleaks", redact)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("mau 1, dapat %d", len(fs))
	}
	f := fs[0]
	if f.Severity != finding.SeverityHigh { // level error → high
		t.Errorf("severity: mau high, dapat %s", f.Severity)
	}
	if got := strings.Join(f.CWE, ","); got != "CWE-798" {
		t.Errorf("CWE string tunggal: mau CWE-798, dapat %q", got)
	}
	if f.Evidence == nil {
		t.Fatal("evidence hilang")
	}
	if strings.Contains(f.Evidence.Matched, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("SECRET BOCOR ke evidence: %q", f.Evidence.Matched)
	}
	if !strings.Contains(f.Evidence.Matched, "REDACTED") {
		t.Errorf("evidence tak teredaksi: %q", f.Evidence.Matched)
	}
}

func TestNormalizeSARIFRedactDropsEvidence(t *testing.T) {
	// redact mengembalikan kosong → evidence tak diisi sama sekali.
	fs, err := NormalizeSARIF([]byte(gitleaksSARIF), "gitleaks", func(string) string { return "" })
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if fs[0].Evidence != nil {
		t.Errorf("redact kosong harus hilangkan evidence, dapat %q", fs[0].Evidence.Matched)
	}
}

func TestNormalizeSARIFEmpty(t *testing.T) {
	fs, err := NormalizeSARIF([]byte(`{"runs":[{"tool":{"driver":{"name":"x","rules":[]}},"results":[]}]}`), "x", nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("mau 0 temuan, dapat %d", len(fs))
	}
}

func TestNormalizeSARIFInvalid(t *testing.T) {
	if _, err := NormalizeSARIF([]byte("bukan json"), "x", nil); err == nil {
		t.Error("mau error pada json rusak")
	}
}
