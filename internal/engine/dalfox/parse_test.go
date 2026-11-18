package dalfox

import (
	"strings"
	"testing"
	"time"

	"bughound/internal/finding"
)

// sampleArray: two PoCs (verified XSS + BAV open-redirect) in array form.
const sampleArray = `[
  {"type":"V","inject_type":"inHTML-URL","method":"GET","data":"https://lab.test/search?q=<svg onload=alert(1)>","param":"q","payload":"<svg onload=alert(1)>","evidence":"12 line: <svg onload=alert(1)>","cwe":"CWE-79","severity":"High","message_str":"Triggered XSS Payload","raw_request":"GET /search?q=x HTTP/1.1\nHost: lab.test\nCookie: session=SUPERSECRET\nAuthorization: Bearer TOKEN123\n\n","raw_response":"HTTP/1.1 200 OK\nSet-Cookie: s=LEAK\n\n<svg onload=alert(1)>"},
  {"type":"G","inject_type":"BAV/open-redirect","method":"GET","data":"https://lab.test/go?url=//evil.test","param":"url","payload":"//evil.test","evidence":"302 Location: //evil.test","cwe":"CWE-601","severity":"Medium"}
]`

func TestParseArray(t *testing.T) {
	fs, err := Parse(strings.NewReader(sampleArray), "https://lab.test", "prog", "run-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 {
		t.Fatalf("must be 2 findings; got %d", len(fs))
	}

	a := fs[0]
	if a.Type != "xss" {
		t.Errorf("type XSS; got %q", a.Type)
	}
	if a.Severity != finding.SeverityHigh {
		t.Errorf("severity high; got %s", a.Severity)
	}
	if a.Confidence != finding.ConfidenceHigh { // type "V" = verified
		t.Errorf("confidence high (V); got %s", a.Confidence)
	}
	if a.SourceEngine != "dalfox" || a.SourceTemplate != "inHTML-URL" {
		t.Errorf("wrong source: %s / %s", a.SourceEngine, a.SourceTemplate)
	}
	if len(a.CWE) != 1 || a.CWE[0] != "CWE-79" {
		t.Errorf("CWE-79; got %v", a.CWE)
	}
	if a.Location.Parameter != "q" || a.Location.Method != "GET" {
		t.Errorf("wrong param/method location: %+v", a.Location)
	}
	if !strings.Contains(a.Location.URL, "svg onload") {
		t.Errorf("the PoC URL must carry the payload; got %q", a.Location.URL)
	}
	if a.Program != "prog" || a.RunID != "run-1" || a.Target != "https://lab.test" {
		t.Errorf("program/run/target not filled: %+v", a)
	}
	if !strings.Contains(a.Title, "XSS") || !strings.Contains(a.Title, "verified") || !strings.Contains(a.Title, "`q`") {
		t.Errorf("the title is not informative enough: %q", a.Title)
	}

	// Secret redaction in the raw evidence.
	if a.Evidence == nil {
		t.Fatal("evidence must be present")
	}
	if strings.Contains(a.Evidence.Request, "SUPERSECRET") || strings.Contains(a.Evidence.Request, "TOKEN123") {
		t.Errorf("secret leaked in the request evidence:\n%s", a.Evidence.Request)
	}
	if !strings.Contains(a.Evidence.Request, "[REDACTED]") {
		t.Errorf("sensitive headers must be redacted:\n%s", a.Evidence.Request)
	}
	if strings.Contains(a.Evidence.ResponseExcerpt, "LEAK") {
		t.Errorf("Set-Cookie must be redacted in the response:\n%s", a.Evidence.ResponseExcerpt)
	}
	if a.Evidence.Payload == "" || a.Evidence.Matched == "" {
		t.Errorf("payload/matched missing: %+v", a.Evidence)
	}

	b := fs[1]
	if b.Type != "open-redirect" {
		t.Errorf("BAV CWE-601 -> open-redirect; got %q", b.Type)
	}
	if b.Severity != finding.SeverityMedium {
		t.Errorf("severity medium; got %s", b.Severity)
	}
	if b.Confidence != finding.ConfidenceLow { // type "G"
		t.Errorf("confidence low (G); got %s", b.Confidence)
	}
}

func TestParseJSONL(t *testing.T) {
	// One PoC object per line (dalfox stream mode).
	jsonl := `{"type":"R","inject_type":"inJS-double","method":"GET","data":"https://lab.test/?x=\"onmouseover=alert(1)","param":"x","payload":"\"onmouseover=alert(1)","evidence":"reflected","cwe":"CWE-79","severity":"High"}
garbage line that is not json
{"type":"V","inject_type":"inHTML","method":"POST","data":"https://lab.test/post","param":"c","payload":"<img src=x>","evidence":"exec","cwe":"CWE-79","severity":"High"}`
	fs, err := Parse(strings.NewReader(jsonl), "https://lab.test", "p", "r")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 {
		t.Fatalf("JSONL must be 2 findings (garbage line skipped); got %d", len(fs))
	}
	if fs[0].Confidence != finding.ConfidenceMedium { // R = reflected
		t.Errorf("R -> medium; got %s", fs[0].Confidence)
	}
	if fs[1].Location.Method != "POST" {
		t.Errorf("method POST; got %q", fs[1].Location.Method)
	}
}

func TestParseResultObject(t *testing.T) {
	// Full Result object form {"pocs":[...],"logs":[...]}.
	res := `{"logs":["start"],"pocs":[{"type":"V","inject_type":"inHTML","method":"GET","data":"https://lab.test/?q=1","param":"q","payload":"<x>","evidence":"e","cwe":"CWE-79","severity":"High"}]}`
	fs, err := Parse(strings.NewReader(res), "https://lab.test", "p", "r")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 {
		t.Fatalf("Result object must be 1 finding; got %d", len(fs))
	}
}

func TestParseEmpty(t *testing.T) {
	fs, err := Parse(strings.NewReader("   \n"), "https://lab.test", "p", "r")
	if err != nil {
		t.Fatalf("empty output must not error: %v", err)
	}
	if len(fs) != 0 {
		t.Fatalf("empty output must be 0 findings; got %d", len(fs))
	}
}

func TestFinalizeCompatibility(t *testing.T) {
	// A mapped finding must pass Finalize (the store calls it): dedup_key,
	// schema, OWASP filled without error.
	fs, _ := Parse(strings.NewReader(sampleArray), "https://lab.test", "p", "r")
	for _, f := range fs {
		f.ID = "test-id" // id set by the store before Finalize (not the adapter)
		if err := f.Finalize(time.Now()); err != nil {
			t.Errorf("Finalize failed for %q: %v", f.Type, err)
		}
		if f.DedupKey == "" || f.SchemaVersion == "" {
			t.Errorf("Finalize must fill dedup_key+schema for %q", f.Type)
		}
	}
}
