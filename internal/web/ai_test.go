package web

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"bughound/internal/aiassist"
	"bughound/internal/audit"
	"bughound/internal/engine"
	"bughound/internal/engine/ffuf"
	"bughound/internal/engine/nuclei"
	"bughound/internal/finding"
	"bughound/internal/recon"
	"bughound/internal/secret"
	"bughound/internal/store"
)

func newAIServer(t *testing.T) (*Server, *store.Mem) {
	t.Helper()
	st := store.NewMem()
	k, _ := secret.NewRandomKey()
	srv, err := NewServer(Config{
		Store:        st,
		Engines:      []engine.Engine{nuclei.Mock{}, ffuf.Mock{}},
		Recon:        recon.MockPipeline{},
		Vault:        secret.NewMemVault(secret.NewKeyring(k)),
		Audit:        audit.NewMemLog([]byte("test-audit-key")),
		AuthDisabled: true,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv, st
}

func saveAITestFinding(t *testing.T, st *store.Mem) *finding.Finding {
	t.Helper()
	f := &finding.Finding{
		Program: "demo", RunID: "r1", Target: "https://demo.test",
		Type: "sqli", Title: "SQLi in q", SourceEngine: "nuclei",
		Severity: finding.SeverityHigh, Confidence: finding.ConfidenceMedium, Status: finding.StatusNew,
		Location: finding.Location{URL: "https://demo.test/x", Method: "GET", Parameter: "q"},
		Evidence: &finding.Evidence{Request: "GET /x\r\nAuthorization: Bearer SECRET\r\n"},
	}
	if _, err := st.Save(context.Background(), f); err != nil {
		t.Fatalf("save finding: %v", err)
	}
	return f
}

func TestAICard_NotConfigured(t *testing.T) {
	srv, st := newAIServer(t)
	f := saveAITestFinding(t, st)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/ai/finding/"+f.ID, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("code %d", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "not enabled yet") {
		t.Fatalf("does not show the configuration prompt:\n%s", body)
	}
}

// TestAICard_ServesFromCacheNoNetwork proves the cache prevents a Claude
// API call (otherwise a Reveal+HTTP to the real endpoint would happen). The key is set so
// aiReady, but a matching cache must short-circuit before the reveal/network.
func TestAICard_ServesFromCacheNoNetwork(t *testing.T) {
	srv, st := newAIServer(t)
	f := saveAITestFinding(t, st)
	if err := srv.vault.Put(context.Background(), aiSecretScope, aiKeyNameAnthropic, []byte("sk-test")); err != nil {
		t.Fatal(err)
	}
	fp := aiassist.Fingerprint(aiInputFrom(f))
	_ = st.PutAIAnalysis(context.Background(), store.AIAnalysis{
		FindingID: f.ID, Program: f.Program, Model: defaultModelAnthropic, SourceHash: fp,
		Payload: `{"why":"reflection","decision":"verify_now","hypotheses":[{"mutation":"q=1'","expected":"SQL error","confirms":"SQLi"}]}`,
	})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/ai/finding/"+f.ID, nil))
	body := rec.Body.String()
	for _, want := range []string{"verify now", "q=1&#39;", "from cache"} {
		if !strings.Contains(body, want) {
			t.Fatalf("the cache card is missing %q:\n%s", want, body)
		}
	}
}

// TestAICard_ErrorPathRenders keeps the card rendering cleanly when GENERATION FAILS (Err set,
// Analysis nil), instead of exploding in the template. The line
// {{if and .Analysis (not .Analysis.Hypotheses)}} must be safe when Analysis is nil.
func TestAICard_ErrorPathRenders(t *testing.T) {
	srv, _ := newAIServer(t)
	var buf bytes.Buffer
	err := srv.pages["ai"].ExecuteTemplate(&buf, "ai_card", aiCardData{
		Ready:     true,
		FindingID: "f1",
		Engine:    "nuclei",
		Safety:    aiSafetyNote,
		Err:       "boom-network",
	})
	if err != nil {
		t.Fatalf("rendering the error path failed (the template exploded when Analysis is nil): %v", err)
	}
	if !strings.Contains(buf.String(), "boom-network") {
		t.Fatalf("the error message is not shown:\n%s", buf.String())
	}
}

func TestAISettings_GETRenders(t *testing.T) {
	srv, _ := newAIServer(t)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/ai/settings", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("code %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "API key Claude") {
		t.Fatalf("the AI settings form is not rendered:\n%s", rec.Body.String())
	}
}

// TestAISettings_RendersBothProviders makes sure the settings page shows
// the provider picker + both blocks (Anthropic & Groq), not only Anthropic.
func TestAISettings_RendersBothProviders(t *testing.T) {
	srv, _ := newAIServer(t)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/ai/settings", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("code %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"Active provider", "Anthropic (Claude)", "API key Groq", defaultModelGroq} {
		if !strings.Contains(body, want) {
			t.Fatalf("settings are missing %q:\n%s", want, body)
		}
	}
}

// TestAISettings_SaveSelectsGroq saves Groq as the active provider through the
// handler (CSRF double-submit), then verifies the active provider/model + the Groq
// key are stored, and the Anthropic model stays separate (not overwritten).
func TestAISettings_SaveSelectsGroq(t *testing.T) {
	srv, _ := newAIServer(t)
	const tok = "tok-csrf-123"
	form := url.Values{
		"csrf":            {tok},
		"provider":        {string(aiassist.ProviderGroq)},
		"anthropic_model": {"claude-haiku-5-5"},
		"groq_model":      {"openai/gpt-oss-120b"},
		"groq_api_key":    {"gsk-secret-xyz"},
	}
	req := httptest.NewRequest("POST", "/ai/settings", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "bh_csrf", Value: tok})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("save = %d, want 303; body: %s", rec.Code, rec.Body.String())
	}
	ctx := context.Background()
	if p := srv.aiProvider(ctx); p != aiassist.ProviderGroq {
		t.Fatalf("active provider = %q, want groq", p)
	}
	if m := srv.aiModel(ctx); m != "openai/gpt-oss-120b" {
		t.Fatalf("active groq model = %q, want openai/gpt-oss-120b", m)
	}
	if !srv.aiKeyPresent(ctx) {
		t.Fatal("the groq key (active provider) must be set after saving")
	}
	// The Anthropic model is stored separately, not overwritten by the Groq choice.
	if m := srv.aiModelFor(ctx, aiassist.ProviderAnthropic); m != "claude-haiku-5-5" {
		t.Fatalf("model anthropic = %q, want claude-haiku-5-5", m)
	}
}

// TestAI_ActiveProviderKeyGating proves aiReady follows the ACTIVE provider's
// key: choosing Groq without a Groq key → not ready even though the Anthropic key is present;
// the model falls back to the Groq default until set.
func TestAI_ActiveProviderKeyGating(t *testing.T) {
	srv, st := newAIServer(t)
	ctx := context.Background()
	if err := st.PutSetting(ctx, aiProviderKey, string(aiassist.ProviderGroq)); err != nil {
		t.Fatal(err)
	}
	if err := srv.vault.Put(ctx, aiSecretScope, aiKeyNameAnthropic, []byte("sk-ant")); err != nil {
		t.Fatal(err)
	}
	if srv.aiProvider(ctx) != aiassist.ProviderGroq {
		t.Fatal("active provider must be groq")
	}
	if srv.aiReady(ctx) {
		t.Fatal("without a groq key, the groq provider must not be ready (the anthropic key does not count)")
	}
	if m := srv.aiModel(ctx); m != defaultModelGroq {
		t.Fatalf("model groq default = %q, want %q", m, defaultModelGroq)
	}
	if err := srv.vault.Put(ctx, aiSecretScope, aiKeyNameGroq, []byte("gsk-test")); err != nil {
		t.Fatal(err)
	}
	if !srv.aiReady(ctx) {
		t.Fatal("with a groq key, the groq provider must be ready")
	}
}
