package nuclei

import (
	"bytes"
	"context"
	"encoding/json"

	"bughound/internal/finding"
)

// Mock adalah engine nuclei palsu untuk M0: ia mengembalikan output sampel yang
// sudah direkam, tanpa pernah menyentuh jaringan. Ini membuat alur ujung-ke-ujung
// (dan E2E) mustahil memicu scan nyata.
type Mock struct{}

// Name memenuhi engine.Engine.
func (Mock) Name() string { return "nuclei (mock)" }

// Scan memenuhi engine.Engine: mengembalikan temuan dari output sampel.
// target/ctx sengaja diabaikan karena tak ada koneksi nyata.
func (Mock) Scan(_ context.Context, _ string, program, runID string) ([]*finding.Finding, error) {
	return Parse(bytes.NewReader(sampleJSONL), program, runID)
}

// SampleJSONL mengembalikan output nuclei sampel (JSONL) untuk demonstrasi/test.
func SampleJSONL() []byte { return sampleJSONL }

// sampleJSONL dibangun dari struct agar newline di request/response ter-escape
// dengan benar (satu event = satu baris), tanpa file eksternal.
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
				Description: "Endpoint mengambil URL dari parameter tanpa validasi, memungkinkan permintaan ke jaringan internal.",
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
				Description:    "File .env dapat diakses publik.",
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
			panic("nuclei: gagal membangun sampel: " + err.Error())
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}
