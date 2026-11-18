package ffuf

import (
	"bytes"
	"context"
	"encoding/json"

	"bughound/internal/finding"
)

// Mock is a fake ffuf engine for M1: it returns recorded sample output without
// touching the network.
type Mock struct{}

// Name satisfies engine.Engine.
func (Mock) Name() string { return "ffuf (mock)" }

// Scan satisfies engine.Engine: it returns findings from the sample output.
func (Mock) Scan(_ context.Context, _ string, program, runID string) ([]*finding.Finding, error) {
	return Parse(bytes.NewReader(sampleJSON), program, runID)
}

var sampleJSON = buildSample()

func buildSample() []byte {
	out := ffufOutput{Results: []ffufResult{
		{Input: map[string]string{"FUZZ": "admin"}, Status: 200, Length: 4096, Words: 200, Lines: 80, ContentType: "text/html", URL: "https://demo.test/admin", Host: "demo.test"},
		{Input: map[string]string{"FUZZ": ".git/config"}, Status: 200, Length: 321, Words: 20, Lines: 10, ContentType: "text/plain", URL: "https://demo.test/.git/config", Host: "demo.test"},
		{Input: map[string]string{"FUZZ": "backup.zip"}, Status: 200, Length: 1048576, Words: 1, Lines: 1, ContentType: "application/zip", URL: "https://demo.test/backup.zip", Host: "demo.test"},
		{Input: map[string]string{"FUZZ": "login"}, Status: 401, Length: 12, Words: 2, Lines: 1, ContentType: "text/html", URL: "https://demo.test/login", Host: "demo.test"},
	}}
	b, err := json.Marshal(out)
	if err != nil {
		panic("ffuf: failed to build sample: " + err.Error())
	}
	return b
}
