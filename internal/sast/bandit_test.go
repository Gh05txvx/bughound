package sast

import (
	"strings"
	"testing"

	"bughound/internal/finding"
)

const sampleBanditJSON = `{
  "results": [
    {
      "filename": "/scan/app/db.py",
      "line_number": 12,
      "test_id": "B608",
      "test_name": "hardcoded_sql_expressions",
      "issue_text": "Possible SQL injection vector through string-based query construction.",
      "issue_severity": "MEDIUM",
      "issue_confidence": "LOW",
      "issue_cwe": {"id": 89, "link": "https://cwe.mitre.org/data/definitions/89.html"},
      "code": "11 q = \"SELECT * FROM users WHERE id = \" + uid\n12 cur.execute(q)\n",
      "more_info": "https://bandit.readthedocs.io/en/1.7.5/plugins/b608.html"
    },
    {
      "filename": "/scan/app/crypto.py",
      "line_number": 3,
      "test_id": "B303",
      "test_name": "md5",
      "issue_text": "Use of insecure MD5 hash function.",
      "issue_severity": "HIGH",
      "issue_confidence": "HIGH",
      "issue_cwe": {"id": 327, "link": "https://cwe.mitre.org/data/definitions/327.html"},
      "code": "3 h = hashlib.md5(data).hexdigest()\n",
      "more_info": "https://bandit.readthedocs.io/md5.html"
    }
  ],
  "errors": []
}`

func TestParseBandit(t *testing.T) {
	fs, err := parseBandit(strings.NewReader(sampleBanditJSON), "/scan")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(fs) != 2 {
		t.Fatalf("want 2 findings, got %d", len(fs))
	}
	sqli := findByType(fs, "B608")
	if sqli == nil {
		t.Fatal("B608 is missing")
	}
	if sqli.Location.URL != "app/db.py:12" { // relative to dir /scan
		t.Errorf("location: want app/db.py:12, got %s", sqli.Location.URL)
	}
	if sqli.Severity != finding.SeverityMedium {
		t.Errorf("severity: want medium, got %s", sqli.Severity)
	}
	if sqli.Confidence != finding.ConfidenceLow {
		t.Errorf("confidence: want low, got %s", sqli.Confidence)
	}
	if got := strings.Join(sqli.CWE, ","); got != "CWE-89" {
		t.Errorf("CWE: want CWE-89, got %q", got)
	}
	if sqli.SourceEngine != "bandit" {
		t.Errorf("wrong source engine: %s", sqli.SourceEngine)
	}
	if sqli.Evidence == nil || !strings.Contains(sqli.Evidence.Matched, "SELECT") {
		t.Error("the evidence code is missing")
	}
	if len(sqli.References) != 2 { // more_info + cwe link
		t.Errorf("want 2 references, got %d (%v)", len(sqli.References), sqli.References)
	}
	md5 := findByType(fs, "B303")
	if md5 == nil || md5.Severity != finding.SeverityHigh || md5.Confidence != finding.ConfidenceHigh {
		t.Errorf("B303: want high/high, got %v", md5)
	}
}

func TestParseBanditEmpty(t *testing.T) {
	fs, err := parseBandit(strings.NewReader(`{"results": [], "errors": []}`), "/scan")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("want 0 findings, got %d", len(fs))
	}
}

func TestParseBanditInvalid(t *testing.T) {
	if _, err := parseBandit(strings.NewReader("not json"), "/scan"); err == nil {
		t.Error("want an error on broken json")
	}
}

func TestBanditRegistered(t *testing.T) {
	if _, ok := Lookup("bandit"); !ok {
		t.Error("the bandit adapter is not registered")
	}
}

func TestMapBanditSeverity(t *testing.T) {
	cases := map[string]finding.Severity{
		"HIGH": finding.SeverityHigh, "MEDIUM": finding.SeverityMedium,
		"LOW": finding.SeverityLow, "": finding.SeverityInfo,
	}
	for in, want := range cases {
		if got := mapBanditSeverity(in); got != want {
			t.Errorf("mapBanditSeverity(%q): want %s, got %s", in, want, got)
		}
	}
}
