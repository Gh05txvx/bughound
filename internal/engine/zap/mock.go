package zap

import (
	"bytes"
	"context"

	"bughound/internal/finding"
)

// Mock is a fake ZAP engine: it returns a recorded sample report (via Parse)
// without touching the network. Used for demo & E2E.
type Mock struct{}

// Name satisfies engine.Engine.
func (Mock) Name() string { return "zap (mock)" }

// Scan satisfies engine.Engine: returns findings from the sample report.
func (Mock) Scan(_ context.Context, _, program, runID string) ([]*finding.Finding, error) {
	return Parse(bytes.NewReader(sampleJSON), program, runID)
}

var sampleJSON = []byte(`{
  "site": [
    {
      "@name": "https://demo.test",
      "alerts": [
        {
          "pluginid": "40018",
          "alert": "SQL Injection",
          "riskcode": "3",
          "confidence": "2",
          "desc": "<p>SQL injection may be possible.</p>",
          "solution": "Use parameterized queries.",
          "reference": "https://owasp.org/www-community/attacks/SQL_Injection",
          "cweid": "89",
          "instances": [
            {"uri": "https://demo.test/item?id=1", "method": "GET", "param": "id", "evidence": "you have an error in your SQL syntax"}
          ]
        },
        {
          "pluginid": "40012",
          "alert": "Cross Site Scripting (Reflected)",
          "riskcode": "2",
          "confidence": "3",
          "desc": "<p>Reflected XSS.</p>",
          "solution": "Encode output.",
          "reference": "https://owasp.org/www-community/attacks/xss/",
          "cweid": "79",
          "instances": [
            {"uri": "https://demo.test/search?q=test", "method": "GET", "param": "q", "evidence": "<script>alert(1)</script>"}
          ]
        }
      ]
    }
  ]
}`)
