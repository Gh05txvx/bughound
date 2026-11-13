package aiassist

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestScrubTextRedacts(t *testing.T) {
	in := "GET /x HTTP/1.1\r\n" +
		"Authorization: Bearer abc.def.ghi\r\n" +
		"Cookie: session=deadbeef\r\n" +
		"X-Api-Key: sk-secret-123\r\n" +
		"body: user=alice@example.com&token=supersecretvalue&q=1"
	out := ScrubText(in, 4096)
	for _, leak := range []string{"abc.def.ghi", "deadbeef", "sk-secret-123", "alice@example.com", "supersecretvalue"} {
		if strings.Contains(out, leak) {
			t.Fatalf("scrub bocor %q dalam:\n%s", leak, out)
		}
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Fatalf("tak ada penanda redaksi:\n%s", out)
	}
	// Header name & non-sensitif tetap ada.
	if !strings.Contains(out, "Authorization:") || !strings.Contains(out, "q=1") {
		t.Fatalf("redaksi terlalu agresif:\n%s", out)
	}
}

func TestScrubTextTruncates(t *testing.T) {
	out := ScrubText(strings.Repeat("a", 500), 100)
	if !strings.Contains(out, "dipangkas") {
		t.Fatalf("tak dipangkas: %q", out)
	}
	if len(out) > 160 {
		t.Fatalf("hasil terlalu panjang: %d", len(out))
	}
}

func TestSeedHintsFor(t *testing.T) {
	if got := SeedHintsFor("sqli", ""); len(got) == 0 {
		t.Fatal("sqli harus punya seed hints")
	}
	if got := SeedHintsFor("", "Reflected XSS di q"); len(got) == 0 {
		t.Fatal("fallback ke title gagal (xss)")
	}
	if got := SeedHintsFor("exposed-path", "robots.txt"); got != nil {
		t.Fatalf("kelas tak dikenal harus nil, dapat %v", got)
	}
}

func TestRenderContextScrubsEvidence(t *testing.T) {
	in := Input{
		Type: "sqli", Title: "SQLi", Severity: "high", SourceEngine: "nuclei",
		URL: "https://demo.test/x", Method: "GET",
		Request: "GET /x\r\nAuthorization: Bearer TOPSECRETTOKEN\r\n",
	}
	ctx := RenderContext(in)
	if strings.Contains(ctx, "TOPSECRETTOKEN") {
		t.Fatalf("konteks membocorkan token:\n%s", ctx)
	}
	if !strings.Contains(ctx, "[REDACTED]") {
		t.Fatalf("konteks tak discrub:\n%s", ctx)
	}
}

func TestFingerprintStableAndSensitive(t *testing.T) {
	a := Input{Type: "sqli", URL: "https://demo.test/x", Parameter: "q"}
	b := Input{Type: "sqli", URL: "https://demo.test/x", Parameter: "q"}
	c := Input{Type: "sqli", URL: "https://demo.test/x", Parameter: "id"}
	if Fingerprint(a) != Fingerprint(b) {
		t.Fatal("fingerprint tak stabil untuk input identik")
	}
	if Fingerprint(a) == Fingerprint(c) {
		t.Fatal("fingerprint tak berubah saat parameter beda")
	}
}

func TestParseAnalysis(t *testing.T) {
	cases := []struct {
		name, in, wantDecision string
		wantErr                bool
	}{
		{"polos", `{"why":"x","decision":"verify_now","hypotheses":[]}`, "verify_now", false},
		{"fenced", "```json\n{\"why\":\"x\",\"decision\":\"likely_fp\",\"hypotheses\":[]}\n```", "likely_fp", false},
		{"prosa", `Tentu. {"why":"x","decision":"needs_more_info","hypotheses":[]} semoga membantu`, "needs_more_info", false},
		{"decision_invalid", `{"why":"x","decision":"PWN","hypotheses":[]}`, "needs_more_info", false},
		{"sampah", `maaf saya tidak bisa`, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			an, err := parseAnalysis(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatal("harusnya error")
				}
				return
			}
			if err != nil {
				t.Fatalf("tak diduga error: %v", err)
			}
			if an.Decision != c.wantDecision {
				t.Fatalf("decision = %q, mau %q", an.Decision, c.wantDecision)
			}
		})
	}
}

// TestAnalyzeAgainstStub membuktikan bentuk request (header + body terscrub) dan
// parsing respons — TANPA menyentuh jaringan nyata.
func TestAnalyzeAgainstStub(t *testing.T) {
	var gotKey, gotVer, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-api-key")
		gotVer = r.Header.Get("anthropic-version")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("content-type", "application/json")
		io.WriteString(w, `{"content":[{"type":"text","text":"{\"why\":\"reflektif\",\"decision\":\"verify_now\",\"hypotheses\":[{\"mutation\":\"q=1' OR 1=1--\",\"expected\":\"beda respons\",\"confirms\":\"SQLi boolean\"}],\"notes\":\"\"}"}],"stop_reason":"end_turn"}`)
	}))
	defer srv.Close()

	c := NewClient("claude-sonnet-5-5")
	c.Endpoint = srv.URL
	c.HTTP = srv.Client()

	in := Input{
		Type: "sqli", Title: "SQLi", Severity: "high", SourceEngine: "nuclei",
		URL: "https://demo.test/x", Method: "GET", Parameter: "q",
		Request:   "GET /x\r\nAuthorization: Bearer LEAKME\r\n",
		SeedHints: SeedHintsFor("sqli", ""),
	}
	an, err := c.Analyze(context.Background(), "sk-test-key", in)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	if gotKey != "sk-test-key" || gotVer != anthropicVersion {
		t.Fatalf("header salah: key=%q ver=%q", gotKey, gotVer)
	}
	if strings.Contains(gotBody, "LEAKME") {
		t.Fatalf("body request membocorkan secret:\n%s", gotBody)
	}
	if an.Decision != "verify_now" || len(an.Hypotheses) != 1 || an.Model != "claude-sonnet-5-5" {
		t.Fatalf("hasil parse salah: %+v", an)
	}
	// Body harus JSON valid yang memuat model.
	var req apiReq
	if json.Unmarshal([]byte(gotBody), &req) != nil || req.Model != "claude-sonnet-5-5" {
		t.Fatalf("body bukan apiReq yang benar: %s", gotBody)
	}
}

func TestAnalyzeErrors(t *testing.T) {
	// Non-200 → error tersanitasi (tak membocorkan isi).
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}`)
	}))
	defer bad.Close()
	c := NewClient("claude-haiku-5-5")
	c.Endpoint, c.HTTP = bad.URL, bad.Client()
	if _, err := c.Analyze(context.Background(), "k", Input{URL: "https://demo.test/"}); err == nil {
		t.Fatal("status 401 harus error")
	}

	// Refusal → error.
	ref := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"content":[],"stop_reason":"refusal"}`)
	}))
	defer ref.Close()
	c.Endpoint, c.HTTP = ref.URL, ref.Client()
	if _, err := c.Analyze(context.Background(), "k", Input{URL: "https://demo.test/"}); err == nil {
		t.Fatal("refusal harus error")
	}

	// Key kosong → error tanpa jaringan.
	if _, err := c.Analyze(context.Background(), "", Input{}); err == nil {
		t.Fatal("key kosong harus error")
	}
}
