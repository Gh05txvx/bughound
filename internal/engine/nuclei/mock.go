package nuclei

import (
	"bytes"
	"context"
	"encoding/json"

	"bughound/internal/finding"
)

// Mock is a fake nuclei engine for M0: it returns recorded sample output without
// ever touching the network. This makes the end-to-end flow (and E2E) unable to
// trigger a real scan.
type Mock struct{}

// Name satisfies engine.Engine.
func (Mock) Name() string { return "nuclei (mock)" }

// Scan satisfies engine.Engine: it returns findings from the sample output.
// target/ctx are intentionally ignored because there is no real connection.
func (Mock) Scan(_ context.Context, _ string, program, runID string) ([]*finding.Finding, error) {
	return Parse(bytes.NewReader(sampleJSONL), program, runID)
}

// sampleJSONL is built from structs so newlines in request/response are escaped
// correctly (one event = one line), without an external file.
var sampleJSONL = buildSample()

func buildSample() []byte {
	events := []nucleiEvent{
		{
			TemplateID:    "ssrf-via-fetch",
			Type:          "http",
			Host:          "https://demo.test",
			MatchedAt:     "https://demo.test/fetch",
			MatcherStatus: true,
			MatcherName:   "cloud-metadata",
			IP:            "127.0.0.1",
			Timestamp:     "2026-10-21T09:14:03Z",
			Request: "POST /fetch HTTP/1.1\r\nHost: demo.test\r\n" +
				"Authorization: Bearer SECRET-abc123\r\nCookie: session=deadbeef\r\n\r\n" +
				"url=http://169.254.169.254/latest/meta-data/",
			Response: "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nami-id\nami-launch-index",
			Info: nucleiInfo{
				Name:        "SSRF via fetch parameter",
				Description: "The endpoint takes a URL from a parameter without validation, allowing requests to the internal network.",
				Severity:    "critical",
				Tags:        stringList{"ssrf", "cloud-metadata"},
				Reference:   stringList{"https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"},
				Classification: nucleiClass{
					CWEID:       stringList{"CWE-918"},
					CVSSMetrics: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:L",
					CVSSScore:   9.3,
				},
			},
		},
		{
			TemplateID:    "exposed-env-file",
			Type:          "http",
			Host:          "https://demo.test",
			MatchedAt:     "https://demo.test/.env",
			MatcherStatus: true,
			Timestamp:     "2026-10-21T09:15:00Z",
			Request:       "GET /.env HTTP/1.1\r\nHost: demo.test\r\n\r\n",
			Response:      "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nAPP_ENV=production",
			Info: nucleiInfo{
				Name:           "Exposed .env configuration file",
				Description:    "The .env file is publicly accessible.",
				Severity:       "medium",
				Tags:           stringList{"exposure", "config"},
				Classification: nucleiClass{CWEID: stringList{"CWE-200"}},
			},
		},
	}

	var buf bytes.Buffer
	for _, e := range events {
		b, err := json.Marshal(e)
		if err != nil {
			panic("nuclei: failed to build sample: " + err.Error())
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}
