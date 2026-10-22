package ffuf

import (
	"bytes"
	"context"
	"encoding/json"

	"bughound/internal/finding"
)

// Mock adalah engine ffuf palsu untuk M1: mengembalikan output sampel terekam,
// tanpa menyentuh jaringan.
type Mock struct{}

// Name memenuhi engine.Engine.
func (Mock) Name() string { return "ffuf (mock)" }

// Scan memenuhi engine.Engine: mengembalikan temuan dari output sampel.
func (Mock) Scan(_ context.Context, _ string, program, runID string) ([]*finding.Finding, error) {
	return Parse(bytes.NewReader(sampleJSON), program, runID)
}

// SampleJSON mengembalikan output ffuf sampel untuk demonstrasi/test.
func SampleJSON() []byte { return sampleJSON }

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
		panic("ffuf: gagal membangun sampel: " + err.Error())
	}
	return b
}
