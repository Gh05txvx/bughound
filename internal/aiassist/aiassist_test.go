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
			t.Fatalf("scrub leaks %q in:\n%s", leak, out)
		}
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Fatalf("no redaction marker:\n%s", out)
	}
	// The header name and non-sensitive parts are still there.
	if !strings.Contains(out, "Authorization:") || !strings.Contains(out, "q=1") {
		t.Fatalf("redaction is too aggressive:\n%s", out)
	}
}

func TestScrubTextTruncates(t *testing.T) {
	out := ScrubText(strings.Repeat("a", 500), 100)
	if !strings.Contains(out, "truncated") {
		t.Fatalf("not truncated: %q", out)
	}
	if len(out) > 160 {
		t.Fatalf("the result is too long: %d", len(out))
	}
}

func TestSeedHintsFor(t *testing.T) {
	if got := SeedHintsFor("sqli", ""); len(got) == 0 {
		t.Fatal("sqli must have seed hints")
	}
	if got := SeedHintsFor("", "Reflected XSS in q"); len(got) == 0 {
		t.Fatal("the fallback to title failed (xss)")
	}
	// clickjacking is known now (key "clickjack"; the title "X-Frame-Options" matches "x-frame").
	if got := SeedHintsFor("clickjacking", "X-Frame-Options missing"); len(got) == 0 {
		t.Fatal("clickjacking must have seed hints")
	}
	// A class that is really unknown → nil.
	if got := SeedHintsFor("business-logic-flaw", ""); got != nil {
		t.Fatalf("an unknown class must be nil, got %v", got)
	}
}

// Per-class routing: the most specific wins (ordering), including the new
// classes produced by the custom detectors (expos/graphql) and other engines.
func TestSeedHintsForRouting(t *testing.T) {
	cases := []struct {
		typ, title string
		wantSub    string // at least one hint must contain this substring
		notSub     string // no hint may contain this (guards the ordering)
	}{
		{"os-command-injection", "", "echo", "OR 1=1"},      // command, NOT sql/generic injection
		{"nosql-injection", "", "$ne", "OR 1=1"},            // nosql, NOT sql
		{"sql-injection", "", "OR 1=1", "echo"},             // sql
		{"bh-exposed-git-config", "", "artifact", ""},       // custom detector → exposure
		{"bh-exposed-env-file", "", "artifact", ""},         // custom detector → exposure
		{"bh-graphql-introspection", "", "introspection", ""}, // custom detector → graphql
		{"jwt-alg-none", "", "alg:none", ""},
		{"ssti-detect", "", "{{7*7}}", ""},
		{"cors-misconfig", "", "ACAO", ""},
		{"local-file-inclusion-lfi", "", "%2e%2e%2f", ""},                   // lfi → hintLFI
		{"path-traversal", "", "%2e%2e%2f", ""},                            // traversal → hintLFI
		{"host-header-injection", "", "X-Forwarded-Host", "Boolean true"},  // host-header wins over the generic "injection" (ordering)
		{"clickjacking", "", "frame-ancestors", ""},                        // clickjack
		{"x-frame-options-missing", "", "frame-ancestors", ""},             // x-frame → hintClickjack
		{"", "Reflected XSS", "svg", ""}, // falls back to title
	}
	for _, c := range cases {
		got := strings.Join(SeedHintsFor(c.typ, c.title), " || ")
		if c.wantSub != "" && !strings.Contains(got, c.wantSub) {
			t.Errorf("SeedHintsFor(%q,%q) does not contain %q:\n%s", c.typ, c.title, c.wantSub, got)
		}
		if c.notSub != "" && strings.Contains(got, c.notSub) {
			t.Errorf("SeedHintsFor(%q,%q) is misrouted, it contains %q (ordering?):\n%s", c.typ, c.title, c.notSub, got)
		}
	}
}

// Binding principle: EVERY seed hint must be non-destructive. This keeps
// destructive verbs from slipping in as the map grows.
func TestSeedHintsAllNonDestructive(t *testing.T) {
	banned := []string{"drop table", "delete from", "truncate", "shutdown", "rm -rf", "destroy", "xp_cmdshell", "into outfile", "webshell "}
	for _, sh := range seedHints {
		for _, h := range sh.hints {
			low := strings.ToLower(h)
			for _, b := range banned {
				if strings.Contains(low, b) {
					t.Errorf("the seed hint for class %q contains the destructive term %q: %s", sh.key, b, h)
				}
			}
		}
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
		t.Fatalf("the context leaks the token:\n%s", ctx)
	}
	if !strings.Contains(ctx, "[REDACTED]") {
		t.Fatalf("the context is not scrubbed:\n%s", ctx)
	}
}

func TestFingerprintStableAndSensitive(t *testing.T) {
	a := Input{Type: "sqli", URL: "https://demo.test/x", Parameter: "q"}
	b := Input{Type: "sqli", URL: "https://demo.test/x", Parameter: "q"}
	c := Input{Type: "sqli", URL: "https://demo.test/x", Parameter: "id"}
	if Fingerprint(a) != Fingerprint(b) {
		t.Fatal("the fingerprint is not stable for identical input")
	}
	if Fingerprint(a) == Fingerprint(c) {
		t.Fatal("the fingerprint does not change when the parameter differs")
	}
}

func TestParseAnalysis(t *testing.T) {
	cases := []struct {
		name, in, wantDecision string
		wantErr                bool
	}{
		{"plain", `{"why":"x","decision":"verify_now","hypotheses":[]}`, "verify_now", false},
		{"fenced", "```json\n{\"why\":\"x\",\"decision\":\"likely_fp\",\"hypotheses\":[]}\n```", "likely_fp", false},
		{"prose", `Sure. {"why":"x","decision":"needs_more_info","hypotheses":[]} hope this helps`, "needs_more_info", false},
		{"decision_invalid", `{"why":"x","decision":"PWN","hypotheses":[]}`, "needs_more_info", false},
		{"garbage", `sorry, I cannot do that`, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			an, err := parseAnalysis(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatal("should be an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if an.Decision != c.wantDecision {
				t.Fatalf("decision = %q, want %q", an.Decision, c.wantDecision)
			}
		})
	}
}

// TestAnalyzeAgainstStub checks the request shape (headers + scrubbed body) and
// the response parsing, WITHOUT touching the real network.
func TestAnalyzeAgainstStub(t *testing.T) {
	var gotKey, gotVer, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-api-key")
		gotVer = r.Header.Get("anthropic-version")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("content-type", "application/json")
		io.WriteString(w, `{"content":[{"type":"text","text":"{\"why\":\"reflected\",\"decision\":\"verify_now\",\"hypotheses\":[{\"mutation\":\"q=1' OR 1=1--\",\"expected\":\"different response\",\"confirms\":\"SQLi boolean\"}],\"notes\":\"\"}"}],"stop_reason":"end_turn"}`)
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
		t.Fatalf("wrong headers: key=%q ver=%q", gotKey, gotVer)
	}
	if strings.Contains(gotBody, "LEAKME") {
		t.Fatalf("the request body leaks the secret:\n%s", gotBody)
	}
	if an.Decision != "verify_now" || len(an.Hypotheses) != 1 || an.Model != "claude-sonnet-5-5" {
		t.Fatalf("wrong parse result: %+v", an)
	}
	// The body must be valid JSON that contains the model.
	var req apiReq
	if json.Unmarshal([]byte(gotBody), &req) != nil || req.Model != "claude-sonnet-5-5" {
		t.Fatalf("the body is not a proper apiReq: %s", gotBody)
	}
}

func TestAnalyzeErrors(t *testing.T) {
	// Non-200 → a sanitized error (it does not leak the content).
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}`)
	}))
	defer bad.Close()
	c := NewClient("claude-haiku-5-5")
	c.Endpoint, c.HTTP = bad.URL, bad.Client()
	if _, err := c.Analyze(context.Background(), "k", Input{URL: "https://demo.test/"}); err == nil {
		t.Fatal("status 401 must be an error")
	}

	// Refusal → error.
	ref := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"content":[],"stop_reason":"refusal"}`)
	}))
	defer ref.Close()
	c.Endpoint, c.HTTP = ref.URL, ref.Client()
	if _, err := c.Analyze(context.Background(), "k", Input{URL: "https://demo.test/"}); err == nil {
		t.Fatal("a refusal must be an error")
	}

	// Empty key → an error without any network.
	if _, err := c.Analyze(context.Background(), "", Input{}); err == nil {
		t.Fatal("an empty key must be an error")
	}
}

// TestAnalyzeSurfacesAPIMessage: the API's error message (e.g. the credit
// balance) MUST be shown so the operator knows the root cause, beyond an opaque
// error type, without leaking the key.
func TestAnalyzeSurfacesAPIMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, `{"type":"error","error":{"type":"invalid_request_error","message":"Your credit balance is too low to access the Anthropic API."}}`)
	}))
	defer srv.Close()
	c := NewClient("claude-sonnet-5-5")
	c.Endpoint, c.HTTP = srv.URL, srv.Client()

	_, err := c.Analyze(context.Background(), "sk-DISTINCTIVE-KEY-9x", Input{URL: "https://demo.test/"})
	if err == nil {
		t.Fatal("status 400 must be an error")
	}
	if !strings.Contains(err.Error(), "credit balance is too low") {
		t.Fatalf("the API message is not shown: %v", err)
	}
	if !strings.Contains(err.Error(), "invalid_request_error") {
		t.Fatalf("the error type is missing: %v", err)
	}
	if strings.Contains(err.Error(), "DISTINCTIVE-KEY-9x") {
		t.Fatalf("the key leaked into the error message: %v", err)
	}
}

// ---- Second path: Groq (OpenAI-compatible API) ----

func TestEndpointPerProvider(t *testing.T) {
	if got := (&Client{}).endpoint(); got != defaultEndpoint {
		t.Errorf("default (anthropic) endpoint = %q", got)
	}
	if got := (&Client{Provider: ProviderGroq}).endpoint(); got != groqEndpoint {
		t.Errorf("groq endpoint = %q", got)
	}
	// The override (tests only) is still honoured.
	if got := (&Client{Provider: ProviderGroq, Endpoint: "http://x"}).endpoint(); got != "http://x" {
		t.Errorf("the endpoint override is not honoured: %q", got)
	}
}

// The Groq request shape: Bearer auth (NOT x-api-key), system as a message with
// role "system", a scrubbed body, parsing of choices[].message.content, all
// without the network.
func TestAnalyzeGroqAgainstStub(t *testing.T) {
	var gotAuth, gotXKey, gotVer, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("authorization")
		gotXKey = r.Header.Get("x-api-key")
		gotVer = r.Header.Get("anthropic-version")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("content-type", "application/json")
		io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"{\"why\":\"x\",\"decision\":\"verify_now\",\"hypotheses\":[]}"},"finish_reason":"stop"}]}`)
	}))
	defer srv.Close()

	c := NewClientFor(ProviderGroq, "openai/gpt-oss-20b")
	c.Endpoint, c.HTTP = srv.URL, srv.Client()

	in := Input{Type: "sqli", URL: "https://demo.test/x", Request: "GET /x\r\nAuthorization: Bearer LEAKME\r\n"}
	an, err := c.Analyze(context.Background(), "gsk-test-key", in)
	if err != nil {
		t.Fatalf("Analyze(groq) error: %v", err)
	}
	if gotAuth != "Bearer gsk-test-key" {
		t.Fatalf("wrong Groq auth header: %q", gotAuth)
	}
	if gotXKey != "" || gotVer != "" {
		t.Fatalf("an Anthropic-only header leaked to Groq: x-api-key=%q ver=%q", gotXKey, gotVer)
	}
	if strings.Contains(gotBody, "LEAKME") {
		t.Fatalf("the Groq body leaks the secret:\n%s", gotBody)
	}
	if an.Decision != "verify_now" || an.Model != "openai/gpt-oss-20b" {
		t.Fatalf("wrong Groq parse result: %+v", an)
	}
	var gr groqReq
	if json.Unmarshal([]byte(gotBody), &gr) != nil || gr.Model != "openai/gpt-oss-20b" ||
		len(gr.Messages) != 2 || gr.Messages[0].Role != "system" || gr.Messages[1].Role != "user" {
		t.Fatalf("the body is not a proper groqReq: %s", gotBody)
	}
}

// Groq errors: the API message is shown with the "Groq" label and the key does not leak.
func TestAnalyzeGroqError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"error":{"message":"Invalid API Key","type":"invalid_request_error","code":"invalid_api_key"}}`)
	}))
	defer srv.Close()
	c := NewClientFor(ProviderGroq, "openai/gpt-oss-20b")
	c.Endpoint, c.HTTP = srv.URL, srv.Client()
	_, err := c.Analyze(context.Background(), "gsk-SECRET-123", Input{URL: "https://demo.test/"})
	if err == nil {
		t.Fatal("a Groq status 401 must be an error")
	}
	if !strings.Contains(err.Error(), "Groq API rejected") {
		t.Fatalf("the Groq provider label is missing: %v", err)
	}
	if !strings.Contains(err.Error(), "Invalid API Key") {
		t.Fatalf("the Groq API message is not shown: %v", err)
	}
	if strings.Contains(err.Error(), "gsk-SECRET-123") {
		t.Fatalf("the key leaked into the error message: %v", err)
	}
}

// TestSanitizeMsg: control characters are removed, whitespace is collapsed, and
// the text is trimmed rune-safely.
func TestSanitizeMsg(t *testing.T) {
	got := sanitizeMsg("line1\n\tline2\x00\x07  end")
	if strings.ContainsAny(got, "\n\t\x00\x07") {
		t.Fatalf("control characters remain: %q", got)
	}
	if strings.Contains(got, "  ") {
		t.Fatalf("double spaces were not collapsed: %q", got)
	}
	long := sanitizeMsg(strings.Repeat("x", 500))
	if rc := len([]rune(long)); rc > 201 { // 200 + ellipsis
		t.Fatalf("not trimmed: %d runes", rc)
	}
	if !strings.HasSuffix(long, "…") {
		t.Fatalf("the trim marker is missing: %q", long)
	}
}
