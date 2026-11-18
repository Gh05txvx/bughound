// Package aiassist produces a what-if analysis (a manual validation plan) for a
// finding by calling the Claude API (Anthropic Messages API).
//
// Properties that matter (in line with BugHound's binding principles):
//   - CONTROLLED EGRESS. The only network destinations of this package are the
//     LLM control-plane endpoints HARDCODED per provider (Anthropic:
//     api.anthropic.com; Groq: api.groq.com). Neither goes through the scope
//     guard or the scan egress proxy (they are not scan targets), and user
//     configuration cannot point them at another host. It uses net/http directly
//     (a controlled client, with no new third-party dependency in an offensive
//     tool) instead of an SDK. Groq uses an OpenAI-compatible API.
//   - EVIDENCE IS SCRUBBED FIRST. Every request/response excerpt is scrubbed
//     (sensitive headers, bearer tokens, API keys, emails, secret params) and
//     trimmed BEFORE it is sent, mirroring analyst/bughound_analyst/scrub.py
//     (BH-DESIGN §6).
//   - ADVISORY. The result is NON-DESTRUCTIVE test suggestions that the hunter
//     runs THEMSELVES in Burp. The app never executes anything; there is no
//     auto-submit.
//
// The API key is NOT stored in this struct; it is supplied per call (revealed
// from the encrypted vault right when it is needed) so it lives as briefly as
// possible.
package aiassist

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Control-plane endpoints per provider (HARDCODED; control-plane egress, NOT
// scan targets, NOT routed through the scope guard/proxy, and user configuration
// cannot point them at another host). Groq uses an OpenAI-compatible API.
const (
	defaultEndpoint = "https://api.anthropic.com/v1/messages"           // Anthropic Messages API
	groqEndpoint    = "https://api.groq.com/openai/v1/chat/completions" // Groq (OpenAI-compatible)
)

// anthropicVersion is the stable API version header (Anthropic only).
const anthropicVersion = "2023-06-01"

// Provider selects the LLM provider. The what-if contract (system prompt,
// scrubbed context, JSON parser, seed hints) is IDENTICAL across providers; only
// the request/response ENVELOPE and the authentication differ. Empty is treated
// as anthropic (the default).
type Provider string

const (
	ProviderAnthropic Provider = "anthropic"
	ProviderGroq      Provider = "groq"
)

// Hypothesis is one concrete, Repeater-ready test the LLM suggests.
type Hypothesis struct {
	Mutation string `json:"mutation"` // the specific change to the request
	Expected string `json:"expected"` // the signal to expect
	Confirms string `json:"confirms"` // what is proven if the signal appears
}

// Analysis is the part of the what-if that the LLM REASONS OUT (cached as
// JSON). The deterministic part (target, seed hints, safety) is built in the web
// layer, not here.
type Analysis struct {
	Why        string       `json:"why"`
	Decision   string       `json:"decision"` // verify_now | likely_fp | needs_more_info
	Hypotheses []Hypothesis `json:"hypotheses"`
	Notes      string       `json:"notes,omitempty"`
	Model      string       `json:"model,omitempty"`
}

// Input is the context of ONE finding (the evidence fields are still raw; they are scrubbed here).
type Input struct {
	Type          string
	Title         string
	Severity      string
	Confidence    string
	OWASP         string
	SourceEngine  string
	URL           string
	Method        string
	Parameter     string
	ParamLocation string
	Payload       string
	Matched       string
	Request       string
	Response      string
	SeedHints     []string
}

// Client calls the LLM API of one provider. HTTP can be overridden in tests
// (no network).
type Client struct {
	HTTP     *http.Client
	Model    string
	Endpoint string   // destination override (tests only); empty = the endpoint HARDCODED per provider
	Provider Provider // empty = anthropic (default, backward-compatible)
}

// NewClient creates an Anthropic client (the default). Kept for compatibility.
func NewClient(model string) *Client { return NewClientFor(ProviderAnthropic, model) }

// NewClientFor creates a client for a given provider. Endpoint is left empty on
// purpose so endpoint() picks the destination HARDCODED per provider.
func NewClientFor(provider Provider, model string) *Client {
	return &Client{
		HTTP:     &http.Client{Timeout: 60 * time.Second},
		Model:    model,
		Provider: provider,
	}
}

func (c *Client) prov() Provider {
	if c.Provider == ProviderGroq {
		return ProviderGroq
	}
	return ProviderAnthropic
}

func (c *Client) endpoint() string {
	if c.Endpoint != "" {
		return c.Endpoint
	}
	if c.prov() == ProviderGroq {
		return groqEndpoint
	}
	return defaultEndpoint
}

// providerLabel = the provider name shown in error messages to the operator.
func (c *Client) providerLabel() string {
	if c.prov() == ProviderGroq {
		return "Groq"
	}
	return "Claude"
}

// ---- Scrub (a faithful port of scrub.py) ----

const redacted = "[REDACTED]"

var (
	reHeader = regexp.MustCompile(`(?im)^(authorization|cookie|set-cookie|x-api-key|x-auth-token|proxy-authorization)\s*:.*$`)
	reBearer = regexp.MustCompile(`(?i)bearer\s+[a-z0-9._\-]+`)
	reEmail  = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	reParam  = regexp.MustCompile(`(?i)\b(token|password|passwd|secret|access_token|api_key|apikey)=[^&\s"']+`)
)

// ScrubText removes credentials and PII from s, then trims it to limit bytes.
func ScrubText(s string, limit int) string {
	if s == "" {
		return ""
	}
	s = reHeader.ReplaceAllStringFunc(s, func(m string) string {
		if name, _, found := strings.Cut(m, ":"); found {
			return name + ": " + redacted
		}
		return redacted
	})
	s = reBearer.ReplaceAllString(s, "Bearer "+redacted)
	s = reParam.ReplaceAllStringFunc(s, func(m string) string {
		if name, _, found := strings.Cut(m, "="); found {
			return name + "=" + redacted
		}
		return redacted
	})
	s = reEmail.ReplaceAllString(s, redacted)
	if len(s) > limit {
		s = s[:limit] + "\n…[truncated]"
	}
	return s
}

// ---- Seed hints (seeds per class; extended from _SEED_HINTS/whatif.py) ----
//
// Seeds for MANUAL verification steps per bug class, taken ONLY from the
// Detection (non-destructive) part of the offensive methodology, with no
// exploitation steps. They flow into the what-if card (the deterministic part)
// AND into the LLM context as a starting point. EVERY step must be
// read-only/reversible (a read, a boolean, a benign marker, a light delay); the
// hunter runs them personally in Burp and respects the RoE.

// Hints shared by related classes (avoids duplication).
var (
	hintExposure = []string{
		"Fetch the artifact (read-only) → confirm the content is real and sensitive, and not a placeholder or decoy.",
		"Check related paths: `.git/HEAD`, `.env.bak`, backups, directory listing.",
		"Assess the impact: is the secret still live? are the credentials valid? (confirm WITHOUT using them).",
	}
	hintGraphql = []string{
		"Pull the full schema through introspection (read-only) → map the queries and mutations.",
		"Test field-level authorization: read sensitive fields with no session / with a low-privilege role.",
		"Note risky mutations WITHOUT running them.",
	}
	hintAccess = []string{
		"Access the endpoint with no session / with a lower-privilege session (read-only).",
		"Compare the responses across roles for the same resource.",
	}
	hintDep = []string{
		"Confirm the component version from a banner/asset (read-only).",
		"Match it to the advisory; check whether the public PoC's preconditions are met BEFORE testing.",
	}
	hintLFI = []string{
		"Path filter bypass (read-only): `%2e%2e%2f`, `....//`, `..%2f`, a `%00`/`%2500` suffix → watch whether normalization is bypassed.",
		"Confirm with a benign file that is sure to exist (e.g. `/etc/hostname` if the RoE allows it), then compare with the normal path; do NOT pull credential files or enumerate in bulk.",
		"Treat LFI→RCE potential (wrappers/logs) as a hypothesis NOTE only; do not trigger techniques that write to or poison files.",
	}
	hintHostHeader = []string{
		"Set `Host:` or `X-Forwarded-Host: evil.test` → watch whether it is reflected in absolute links/redirects/responses (read-only).",
		"Record possible password-reset/cache poisoning through Host as a HYPOTHESIS; do not trigger mass email or write to a shared cache.",
	}
	hintClickjack = []string{
		"Check `X-Frame-Options` / CSP `frame-ancestors`. If it is missing or loose, confirm framing with your own LOCAL HTML PoC page (nothing is sent to the target).",
		"Check whether a sensitive one-click action is worth a UI-redress case; real impact needs victim interaction.",
	}
)

var seedHints = []struct {
	key   string
	hints []string
}{
	// Most specific FIRST (the first matching substring wins).
	{"command", []string{"Benign marker: `;echo bh$((7*7))` → look for `bh49` in the response (harmless).", "Light time-based `| sleep 5` → compare latency; respect the RoE/rate limit."}},
	{"rce", []string{"Benign arithmetic/echo marker → look for the computed result in the response.", "Light time-based test + latency comparison; do NOT run commands that change the system."}},
	{"nosql", []string{"Operators: `param[$ne]=` or `param[$regex]=^a` → compare true vs false.", "Auth field `{\"$gt\":\"\"}` (read-only)."}},
	{"sql", []string{"Boolean: `' OR 1=1--` vs `' AND 1=2--` → compare size/content.", "Light time-based: `'||SLEEP(5)` / `';WAITFOR DELAY '0:0:5'--` (non-destructive).", "Error-based: a single `'` → look for an SQL error."}},
	{"ssti", []string{"Polyglot probe: `${7*7}` / `{{7*7}}` / `#{7*7}` → look for `49`.", "Work out the engine from the syntax that gets evaluated; do not touch dangerous objects."}},
	{"xxe", []string{"Declare a benign internal entity → check for expansion in the response.", "Test whether DOCTYPE/DTD is accepted; do NOT pull system files or go OOB without the RoE."}},
	{"lfi", hintLFI},
	{"traversal", hintLFI},
	{"ssrf", []string{"Point it at a callback you CONTROL (OAST); respect the RoE.", "Cloud metadata `169.254.169.254` ONLY when it is explicitly in scope.", "Compare the responses for internal vs external hosts (read-only)."}},
	{"xss", []string{"Reflected context break: `\"><svg onload=…>`.", "Work out the context (HTML/attribute/JS), then adapt the escape breaker.", "Check whether the output is encoded in one context but gets through in another."}},
	{"idor", []string{"Increment/decrement the object id (read-only).", "Swap in an id that belongs to another account → watch whether data leaks.", "Change the method/representation (GET vs POST) for the same endpoint.", "CHAIN (note): if PII/tokens/resets leak, assess the path to account takeover, only on your own TEST account."}},
	{"redirect", []string{"Set the destination to an external host you control → check whether the Location/redirect is followed.", "Try variants: `//evil.test`, `/\\evil.test`, `https:evil.test`.", "If there is an allowlist: insert an allowlisted host as a substring/param (`https://evil.test/?x=allowed.host`, `https://allowed.host@evil.test`) → check whether the filter is bypassed (read-only).", "CHAIN (note): an open redirect often strengthens SSRF or theft of the OAuth `redirect_uri` token; follow it up only when it is in scope and the RoE allows it."}},
	{"host-header", hintHostHeader},
	{"jwt", []string{"Test `alg:none` (strip the signature) → check whether it is accepted.", "Try RS256→HS256 with the public key as the secret (if it leaked).", "Change a non-critical claim → check whether the signature is verified."}},
	{"cors", []string{"`Origin: https://evil.test` → check whether ACAO reflects it + ACAC:true.", "Test the `null` origin and a random subdomain.", "CHAIN (note): an ACAO that reflects the origin + ACAC:true → the attacker's origin can read credentialed responses (a path to ATO); confirm read-only."}},
	{"csrf", []string{"Replay a state-changing action without the token/Origin on your own TEST account → check whether it is accepted.", "Inspect the SameSite attribute of the session cookie."}},
	{"graphql", hintGraphql},
	{"introspect", hintGraphql},
	{"clickjack", hintClickjack},
	{"x-frame", hintClickjack},
	{"secret", hintExposure},
	{"expos", hintExposure},
	{"disclosure", hintExposure},
	{"upload", []string{"Upload a BENIGN file (text/small image) → check the type/extension/name validation.", "Check whether the uploaded path is executable; do NOT upload a webshell."}},
	{"deserial", []string{"Watch whether a serialized object is accepted in a parameter.", "Change a benign field → look for a type error; do not send a gadget chain."}},
	{"cve", hintDep},
	{"outdated", hintDep},
	{"access", hintAccess},
	{"authoriz", hintAccess},
	{"injection", []string{"Boolean true-vs-false (compare the responses).", "A light marker/delay that suits the interpreter; start with the least harmful one."}},
}

// SeedHintsFor returns the deterministic seed hints for a finding's bug class.
func SeedHintsFor(typ, title string) []string {
	t := strings.ToLower(typ)
	if t == "" {
		t = strings.ToLower(title)
	}
	for _, sh := range seedHints {
		if strings.Contains(t, sh.key) {
			return sh.hints
		}
	}
	return nil
}

// ---- Prompt ----

const systemPrompt = `You are a validation assistant for a bug bounty hunter. Given ONE DAST finding (the evidence is already scrubbed), your job is to judge whether it is worth verifying manually and to draw up a NON-DESTRUCTIVE test plan that the hunter will run THEMSELVES in Burp Repeater.

Hard rules:
- Only non-destructive, reversible tests (boolean true/false, light time-based, changing one parameter, reading an object). NEVER suggest: DoS, changing or deleting data, destructive exploits, mass enumeration, or actions that change authorization state.
- Respect the program's Rules of Engagement and rate limit. You do NOT execute anything. You only suggest, and the hunter runs the tests by hand.
- Do not suggest touching out-of-scope or third-party assets (e.g. SSRF to cloud metadata), except as a cautionary note that defers to the RoE.
- Do not invent evidence. If the evidence is not enough to reach a conclusion, say so and set decision "needs_more_info".

Answer with ONLY one valid JSON object, with no other text and no code fence:
{"why":"...","decision":"verify_now|likely_fp|needs_more_info","hypotheses":[{"mutation":"...","expected":"...","confirms":"..."}],"notes":"..."}
- why: 1-3 sentences on why this looks real (or why it may be a false positive).
- hypotheses: 1-4 concrete tests ready for Repeater. mutation=the specific change to the request; expected=the signal you expect; confirms=what is proven if the signal appears.
- notes: optional (may be an empty string).`

// RenderContext builds the user message (the scrubbed finding context). It is
// exported so the web layer can compute a deterministic cache fingerprint.
func RenderContext(in Input) string {
	var b strings.Builder
	b.WriteString("Finding:\n")
	fmt.Fprintf(&b, "- type: %s\n", in.Type)
	fmt.Fprintf(&b, "- title: %s\n", in.Title)
	fmt.Fprintf(&b, "- severity: %s · confidence: %s · owasp: %s\n", in.Severity, in.Confidence, orDash(in.OWASP))
	fmt.Fprintf(&b, "- engine: %s\n", in.SourceEngine)
	fmt.Fprintf(&b, "- target: %s %s\n", orDash(in.Method), in.URL)
	if in.Parameter != "" {
		fmt.Fprintf(&b, "- parameter: %s (%s)\n", in.Parameter, orDash(in.ParamLocation))
	}
	b.WriteString("\nEvidence (scrubbed):\n")
	writeEv(&b, "payload", ScrubText(in.Payload, 256))
	writeEv(&b, "matched", ScrubText(in.Matched, 256))
	writeEv(&b, "request (excerpt)", ScrubText(in.Request, 1024))
	writeEv(&b, "response (excerpt)", ScrubText(in.Response, 512))
	if len(in.SeedHints) > 0 {
		fmt.Fprintf(&b, "\nSeed hints (deterministic; adapt them to the context, or reject them if they do not fit): %s\n", strings.Join(in.SeedHints, "; "))
	}
	return b.String()
}

func writeEv(b *strings.Builder, label, val string) {
	if strings.TrimSpace(val) == "" {
		return
	}
	fmt.Fprintf(b, "- %s: %s\n", label, val)
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

// Fingerprint is a stable hash of the scrubbed context. It is the cache validity key.
func Fingerprint(in Input) string {
	sum := sha256.Sum256([]byte(RenderContext(in)))
	return hex.EncodeToString(sum[:])
}

// ---- API call ----

type apiMsg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type apiReq struct {
	Model     string   `json:"model"`
	MaxTokens int      `json:"max_tokens"`
	System    string   `json:"system,omitempty"`
	Messages  []apiMsg `json:"messages"`
}

type apiResp struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	StopReason string `json:"stop_reason"`
	Error      *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

// ---- Groq (OpenAI-compatible API: Chat Completions) ----

type groqReq struct {
	Model     string   `json:"model"`
	MaxTokens int      `json:"max_tokens"`
	Messages  []apiMsg `json:"messages"` // system = the message with role "system"
}

type groqResp struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
		Code    string `json:"code"`
	} `json:"error"`
}

// apiError unifies API errors across providers for messages to the operator.
type apiError struct{ Type, Message string }

// marshalReq builds the request body in the provider's envelope.
func (c *Client) marshalReq(userMsg string) ([]byte, error) {
	if c.prov() == ProviderGroq {
		return json.Marshal(groqReq{
			Model: c.Model, MaxTokens: 3000,
			Messages: []apiMsg{{Role: "system", Content: systemPrompt}, {Role: "user", Content: userMsg}},
		})
	}
	return json.Marshal(apiReq{
		Model: c.Model, MaxTokens: 3000, System: systemPrompt,
		Messages: []apiMsg{{Role: "user", Content: userMsg}},
	})
}

// setHeaders sets the authentication per provider (the key goes only in a header and is not logged).
func (c *Client) setHeaders(r *http.Request, apiKey string) {
	r.Header.Set("content-type", "application/json")
	if c.prov() == ProviderGroq {
		r.Header.Set("authorization", "Bearer "+apiKey)
		return
	}
	r.Header.Set("x-api-key", apiKey)
	r.Header.Set("anthropic-version", anthropicVersion)
}

// decode extracts the answer text, the API error and a refusal (safety) from the
// raw body according to the provider's envelope.
func (c *Client) decode(raw []byte) (text string, apiErr *apiError, refused bool) {
	if c.prov() == ProviderGroq {
		var gr groqResp
		_ = json.Unmarshal(raw, &gr)
		if gr.Error != nil && (gr.Error.Message != "" || gr.Error.Type != "" || gr.Error.Code != "") {
			apiErr = &apiError{Type: firstNonEmpty(gr.Error.Type, gr.Error.Code), Message: gr.Error.Message}
		}
		var b strings.Builder
		for _, ch := range gr.Choices {
			b.WriteString(ch.Message.Content)
			if ch.FinishReason == "content_filter" {
				refused = true
			}
		}
		return b.String(), apiErr, refused
	}
	var ar apiResp
	_ = json.Unmarshal(raw, &ar)
	if ar.Error != nil && (ar.Error.Message != "" || ar.Error.Type != "") {
		apiErr = &apiError{Type: ar.Error.Type, Message: ar.Error.Message}
	}
	var b strings.Builder
	for _, blk := range ar.Content {
		if blk.Type == "text" {
			b.WriteString(blk.Text)
		}
	}
	return b.String(), apiErr, ar.StopReason == "refusal"
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// Analyze calls Claude with the scrubbed finding context and returns a
// structured analysis. apiKey is supplied per call and is NOT stored or logged.
func (c *Client) Analyze(ctx context.Context, apiKey string, in Input) (Analysis, error) {
	if strings.TrimSpace(apiKey) == "" {
		return Analysis{}, fmt.Errorf("aiassist: API key is empty")
	}
	reqBody, err := c.marshalReq(RenderContext(in))
	if err != nil {
		return Analysis{}, fmt.Errorf("aiassist: encode: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint(), bytes.NewReader(reqBody))
	if err != nil {
		return Analysis{}, fmt.Errorf("aiassist: request: %w", err)
	}
	c.setHeaders(httpReq, apiKey)

	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return Analysis{}, fmt.Errorf("aiassist: connection to the %s API failed", c.providerLabel())
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	text, apiErr, refused := c.decode(raw)

	if resp.StatusCode != http.StatusOK {
		// Show the API's error type + message so the operator knows the root cause
		// (e.g. "credit balance too low", a model that is not available, the
		// version). The message is the provider's feedback on the request/account
		// and is NOT our secret: the API never echoes our key or body. It is
		// sanitized (control characters removed) and trimmed so it is safe for the
		// UI; it does not go into the audit.
		if apiErr != nil && (apiErr.Type != "" || apiErr.Message != "") {
			if msg := sanitizeMsg(apiErr.Message); msg != "" {
				return Analysis{}, fmt.Errorf("aiassist: %s API rejected the request (%s): %s", c.providerLabel(), sanitize(apiErr.Type), msg)
			}
			return Analysis{}, fmt.Errorf("aiassist: %s API rejected the request (%s)", c.providerLabel(), sanitize(apiErr.Type))
		}
		return Analysis{}, fmt.Errorf("aiassist: %s API status %d", c.providerLabel(), resp.StatusCode)
	}
	if refused {
		return Analysis{}, fmt.Errorf("aiassist: %s refused to analyze (safety)", c.providerLabel())
	}
	an, err := parseAnalysis(text)
	if err != nil {
		return Analysis{}, err
	}
	an.Model = c.Model
	return an, nil
}

// parseAnalysis extracts the JSON object from the reply text (tolerating a
// fence or wrapping prose), then validates decision.
func parseAnalysis(text string) (Analysis, error) {
	s := strings.TrimSpace(text)
	s = strings.TrimPrefix(s, "```json")
	s = strings.TrimPrefix(s, "```")
	s = strings.TrimSuffix(s, "```")
	// Take from the first '{' to the last '}' (drops wrapping prose).
	if i := strings.IndexByte(s, '{'); i >= 0 {
		if j := strings.LastIndexByte(s, '}'); j >= i {
			s = s[i : j+1]
		}
	}
	var an Analysis
	if err := json.Unmarshal([]byte(strings.TrimSpace(s)), &an); err != nil {
		return Analysis{}, fmt.Errorf("aiassist: cannot parse the AI response")
	}
	switch an.Decision {
	case "verify_now", "likely_fp", "needs_more_info":
	default:
		an.Decision = "needs_more_info"
	}
	return an, nil
}

// sanitize trims an error token to safe characters (against injection into the UI/log).
func sanitize(s string) string {
	s = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '_' || r == '-' || r == ' ' {
			return r
		}
		return -1
	}, s)
	if len(s) > 60 {
		s = s[:60]
	}
	return s
}

// sanitizeMsg cleans up an API error message for display to the operator: it
// removes control characters (against injection into the UI/log), collapses
// extra whitespace and trims rune-safely. The message is request/account
// feedback from Anthropic (balance, model name, version), not our key or
// evidence.
func sanitizeMsg(s string) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t' || r == '\r':
			return ' '
		case r < 0x20 || r == 0x7f:
			return -1
		default:
			return r
		}
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	const max = 200
	if rs := []rune(s); len(rs) > max {
		s = string(rs[:max]) + "…"
	}
	return s
}
