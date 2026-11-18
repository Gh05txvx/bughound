package sast

import (
	"strings"
	"testing"

	"bughound/internal/finding"
)

// codeqlSARIF: CodeQL style. Rules with a numeric security-severity + tags
// external/cwe/cwe-###; results point at a rule through ruleIndex.
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

// gitleaksSARIF: gitleaks style. Level error, cwe as a single string, a snippet
// holding a secret (it must be redactable).
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
		t.Fatalf("want 2 findings, got %d", len(fs))
	}
	sqli := findByType(fs, "js/sql-injection")
	if sqli == nil {
		t.Fatal("the sql-injection finding is missing")
	}
	// security-severity 9.8 → critical (wins over level error=high).
	if sqli.Severity != finding.SeverityCritical {
		t.Errorf("severity: want critical, got %s", sqli.Severity)
	}
	if sqli.Location.URL != "src/db.js:42" {
		t.Errorf("location: want src/db.js:42, got %s", sqli.Location.URL)
	}
	if sqli.Title != "Database query built from user-controlled sources" {
		t.Errorf("wrong title from shortDescription: %q", sqli.Title)
	}
	if sqli.SourceEngine != "codeql" {
		t.Errorf("source engine: want codeql, got %s", sqli.SourceEngine)
	}
	if got := strings.Join(sqli.CWE, ","); got != "CWE-89" {
		t.Errorf("CWE from tag external/cwe/cwe-089: want CWE-89, got %q", got)
	}
	// Technical tags (external/cwe/..., precision/...) are dropped from the displayed Tags.
	for _, tag := range sqli.Tags {
		if strings.Contains(tag, "/") {
			t.Errorf("a technical tag leaked into Tags: %q", tag)
		}
	}
	if sqli.Evidence == nil || !strings.Contains(sqli.Evidence.Matched, "SELECT") {
		t.Errorf("the evidence snippet is missing")
	}
	// security-severity 5.0 → medium.
	rand := findByType(fs, "js/weak-rand")
	if rand == nil || rand.Severity != finding.SeverityMedium {
		t.Errorf("weak-rand: want medium, got %v", rand)
	}
	if rand.Evidence != nil {
		t.Errorf("without a snippet there should be no evidence, got %q", rand.Evidence.Matched)
	}
}

func TestNormalizeSARIFGitleaksRedaction(t *testing.T) {
	// redact: replace the value after '=' with a mask (simulates secret redaction).
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
		t.Fatalf("want 1, got %d", len(fs))
	}
	f := fs[0]
	if f.Severity != finding.SeverityHigh { // level error → high
		t.Errorf("severity: want high, got %s", f.Severity)
	}
	if got := strings.Join(f.CWE, ","); got != "CWE-798" {
		t.Errorf("single-string CWE: want CWE-798, got %q", got)
	}
	if f.Evidence == nil {
		t.Fatal("the evidence is missing")
	}
	if strings.Contains(f.Evidence.Matched, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("SECRET LEAKED into the evidence: %q", f.Evidence.Matched)
	}
	if !strings.Contains(f.Evidence.Matched, "REDACTED") {
		t.Errorf("the evidence is not redacted: %q", f.Evidence.Matched)
	}
}

func TestNormalizeSARIFRedactDropsEvidence(t *testing.T) {
	// redact returns empty → the evidence is not filled in at all.
	fs, err := NormalizeSARIF([]byte(gitleaksSARIF), "gitleaks", func(string) string { return "" })
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if fs[0].Evidence != nil {
		t.Errorf("an empty redact must drop the evidence, got %q", fs[0].Evidence.Matched)
	}
}

func TestNormalizeSARIFEmpty(t *testing.T) {
	fs, err := NormalizeSARIF([]byte(`{"runs":[{"tool":{"driver":{"name":"x","rules":[]}},"results":[]}]}`), "x", nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("want 0 findings, got %d", len(fs))
	}
}

func TestNormalizeSARIFInvalid(t *testing.T) {
	if _, err := NormalizeSARIF([]byte("not json"), "x", nil); err == nil {
		t.Error("want an error on broken json")
	}
}
