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
		t.Fatalf("mau 2 temuan, dapat %d", len(fs))
	}
	sqli := findByType(fs, "B608")
	if sqli == nil {
		t.Fatal("B608 hilang")
	}
	if sqli.Location.URL != "app/db.py:12" { // relatif thd dir /scan
		t.Errorf("location: mau app/db.py:12, dapat %s", sqli.Location.URL)
	}
	if sqli.Severity != finding.SeverityMedium {
		t.Errorf("severity: mau medium, dapat %s", sqli.Severity)
	}
	if sqli.Confidence != finding.ConfidenceLow {
		t.Errorf("confidence: mau low, dapat %s", sqli.Confidence)
	}
	if got := strings.Join(sqli.CWE, ","); got != "CWE-89" {
		t.Errorf("CWE: mau CWE-89, dapat %q", got)
	}
	if sqli.SourceEngine != "bandit" {
		t.Errorf("source engine salah: %s", sqli.SourceEngine)
	}
	if sqli.Evidence == nil || !strings.Contains(sqli.Evidence.Matched, "SELECT") {
		t.Error("evidence code hilang")
	}
	if len(sqli.References) != 2 { // more_info + cwe link
		t.Errorf("mau 2 referensi, dapat %d (%v)", len(sqli.References), sqli.References)
	}
	md5 := findByType(fs, "B303")
	if md5 == nil || md5.Severity != finding.SeverityHigh || md5.Confidence != finding.ConfidenceHigh {
		t.Errorf("B303: mau high/high, dapat %v", md5)
	}
}

func TestParseBanditEmpty(t *testing.T) {
	fs, err := parseBandit(strings.NewReader(`{"results": [], "errors": []}`), "/scan")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("mau 0 temuan, dapat %d", len(fs))
	}
}

func TestParseBanditInvalid(t *testing.T) {
	if _, err := parseBandit(strings.NewReader("bukan json"), "/scan"); err == nil {
		t.Error("mau error pada json rusak")
	}
}

func TestBanditRegistered(t *testing.T) {
	if _, ok := Lookup("bandit"); !ok {
		t.Error("adapter bandit tak terdaftar")
	}
}

func TestMapBanditSeverity(t *testing.T) {
	cases := map[string]finding.Severity{
		"HIGH": finding.SeverityHigh, "MEDIUM": finding.SeverityMedium,
		"LOW": finding.SeverityLow, "": finding.SeverityInfo,
	}
	for in, want := range cases {
		if got := mapBanditSeverity(in); got != want {
			t.Errorf("mapBanditSeverity(%q): mau %s, dapat %s", in, want, got)
		}
	}
}
