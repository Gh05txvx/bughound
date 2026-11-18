package web

// MCP/AI integration: the web menu for entering a Claude API key (stored in the
// encrypted vault) + a per-finding what-if card produced by the Claude API and cached.
//
// Security boundaries (BugHound's binding principles):
//   - API key = secret: via the encrypted vault (scope "ai"), redacted, never
//     written to a log/report/commit, access auto-audited by the vault reveal hook.
//   - Egress to api.anthropic.com = an opt-in, audited control plane, SEPARATE from
//     the scan scope guard/proxy (see internal/aiassist). Active only when a key is set.
//   - Evidence is scrubbed before it is sent (aiassist.ScrubText).
//   - Advisory: the card = a manual validation plan; Burp execution stays manual, with
//     no auto-submit.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"bughound/internal/aiassist"
	"bughound/internal/audit"
	"bughound/internal/auth"
	"bughound/internal/finding"
	"bughound/internal/store"
)

const (
	aiSecretScope = "ai"
	// The vault secret name per provider. Anthropic uses "api_key" (KEPT so the old
	// key still reads); Groq is separate so both can be stored.
	aiKeyNameAnthropic = "api_key"
	aiKeyNameGroq      = "groq_api_key"

	aiProviderKey = "ai_provider" // setting: the active provider ("anthropic"|"groq")
	// The model setting per provider (separate so switching provider does not overwrite the other).
	aiModelKeyAnthropic = "ai_model"      // KEPT (backward-compat)
	aiModelKeyGroq      = "ai_model_groq" // Groq model = free text (the ID changes often)

	defaultModelAnthropic = "claude-sonnet-5-5"
	defaultModelGroq      = "openai/gpt-oss-20b" // a sensible default; replaceable (Groq IDs change often)

	aiSafetyNote = "Non-destructive only (light boolean/time, read-only). Respect the program rate limit & RoE. Run it MANUALLY in Burp Repeater — no auto-submit."
)

// aiModels is the Claude models that may be chosen (whitelist; Anthropic IDs are stable).
// Default = Sonnet (cheap, replaceable). Opus = the deepest reasoning.
var aiModels = []struct{ ID, Label string }{
	{"claude-sonnet-5-5", "Claude Sonnet 5.5, balanced (cheap, default)"},
	{"claude-opus-5-5", "Claude Opus 5.5, deepest reasoning (expensive)"},
	{"claude-haiku-5-5", "Claude Haiku 5.5, cheapest & fastest"},
}

// aiProviders = the providers that can be chosen in settings.
var aiProviders = []struct {
	ID    aiassist.Provider
	Label string
}{
	{aiassist.ProviderAnthropic, "Anthropic (Claude), paid, high quality"},
	{aiassist.ProviderGroq, "Groq, free tier, open models (Llama/GPT-OSS), very fast"},
}

func validAIModel(m string) bool {
	for _, x := range aiModels {
		if x.ID == m {
			return true
		}
	}
	return false
}

// looksLikeModelID keeps the Groq model (free text) to a reasonable ID charset:
// letters/digits/`-._/:` (e.g. "openai/gpt-oss-20b", "llama-3.3-70b-versatile").
// It blocks injection/noise; a retired ID is rejected by Groq with a clear message.
func looksLikeModelID(m string) bool {
	m = strings.TrimSpace(m)
	if m == "" || len(m) > 80 {
		return false
	}
	for _, r := range m {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-' || r == '.' || r == '_' || r == '/' || r == ':':
		default:
			return false
		}
	}
	return true
}

// aiProvider returns the active provider from settings (default anthropic).
func (s *Server) aiProvider(ctx context.Context) aiassist.Provider {
	if s.aistore != nil {
		if v, _ := s.aistore.GetSetting(ctx, aiProviderKey); v == string(aiassist.ProviderGroq) {
			return aiassist.ProviderGroq
		}
	}
	return aiassist.ProviderAnthropic
}

func aiKeyNameFor(p aiassist.Provider) string {
	if p == aiassist.ProviderGroq {
		return aiKeyNameGroq
	}
	return aiKeyNameAnthropic
}

func aiModelSettingKeyFor(p aiassist.Provider) string {
	if p == aiassist.ProviderGroq {
		return aiModelKeyGroq
	}
	return aiModelKeyAnthropic
}

func defaultModelFor(p aiassist.Provider) string {
	if p == aiassist.ProviderGroq {
		return defaultModelGroq
	}
	return defaultModelAnthropic
}

// validModelFor validates the model against the provider: a whitelist for Anthropic,
// a free ID charset for Groq (its list changes fast).
func validModelFor(p aiassist.Provider, m string) bool {
	if p == aiassist.ProviderGroq {
		return looksLikeModelID(m)
	}
	return validAIModel(m)
}

// ---- configuration helpers ----

// aiKeyPresent reports whether the ACTIVE provider's key is set.
func (s *Server) aiKeyPresent(ctx context.Context) bool {
	return s.aiKeyMeta(ctx, aiKeyNameFor(s.aiProvider(ctx))).present
}

type aiKeyMeta struct {
	present bool
	updated string
}

// aiKeyMeta looks up the status of one secret (per name) in the "ai" scope vault.
func (s *Server) aiKeyMeta(ctx context.Context, name string) aiKeyMeta {
	if s.vault == nil {
		return aiKeyMeta{}
	}
	metas, err := s.vault.List(ctx, aiSecretScope)
	if err != nil {
		return aiKeyMeta{}
	}
	for _, m := range metas {
		if m.Name == name {
			out := aiKeyMeta{present: true}
			if !m.UpdatedAt.IsZero() {
				out.updated = m.UpdatedAt.Format("2006-01-02 15:04Z")
			}
			return out
		}
	}
	return aiKeyMeta{}
}

// aiReady reports whether the AI feature is ready to use (store supports it + vault present +
// key set).
func (s *Server) aiReady(ctx context.Context) bool {
	return s.aistore != nil && s.vault != nil && s.aiKeyPresent(ctx)
}

// aiModel returns the model for the ACTIVE provider (validated per provider).
func (s *Server) aiModel(ctx context.Context) string {
	return s.aiModelFor(ctx, s.aiProvider(ctx))
}

func (s *Server) aiModelFor(ctx context.Context, p aiassist.Provider) string {
	if s.aistore != nil {
		if m, _ := s.aistore.GetSetting(ctx, aiModelSettingKeyFor(p)); validModelFor(p, m) {
			return m
		}
	}
	return defaultModelFor(p)
}

// aiLock gives one lock per finding so two concurrent opens do not trigger two
// Claude calls (avoiding a double bill).
func (s *Server) aiLock(id string) func() {
	actual, _ := s.aiGen.LoadOrStore(id, &sync.Mutex{})
	mu := actual.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

func aiInputFrom(f *finding.Finding) aiassist.Input {
	in := aiassist.Input{
		Type: f.Type, Title: f.Title,
		Severity: string(f.Severity), Confidence: string(f.Confidence),
		OWASP: string(f.OWASP), SourceEngine: f.SourceEngine,
		URL: f.Location.URL, Method: f.Location.Method,
		Parameter: f.Location.Parameter, ParamLocation: string(f.Location.ParamLocation),
		SeedHints: aiassist.SeedHintsFor(f.Type, f.Title),
	}
	if f.Evidence != nil {
		in.Payload = f.Evidence.Payload
		in.Matched = f.Evidence.Matched
		in.Request = f.Evidence.Request
		in.Response = f.Evidence.ResponseExcerpt
	}
	return in
}

// ---- MCP/AI settings page ----

type aiSettingsData struct {
	Nav, Title, Program, CSRF string // Program is used by base.html (nav) — always empty here
	Available                 bool   // store+vault support it
	Provider                  string // the active provider ("anthropic"|"groq")
	Providers                 []aiProviderView
	// Anthropic (model = dropdown whitelist)
	AnthropicKeyPresent bool
	AnthropicKeyUpdated string
	AnthropicModels     []aiModelView
	// Groq (model = free text; the ID changes fast)
	GroqKeyPresent bool
	GroqKeyUpdated string
	GroqModel      string
	Saved          bool
}

type aiModelView struct {
	ID       string
	Label    string
	Selected bool
}

type aiProviderView struct {
	ID       string
	Label    string
	Selected bool
}

func (s *Server) aiSettingsData(r *http.Request) aiSettingsData {
	ctx := r.Context()
	active := s.aiProvider(ctx)
	d := aiSettingsData{
		Nav: "ai", Title: "MCP / AI", CSRF: s.csrfToken(r),
		Available: s.aistore != nil && s.vault != nil,
		Provider:  string(active),
	}
	for _, p := range aiProviders {
		d.Providers = append(d.Providers, aiProviderView{ID: string(p.ID), Label: p.Label, Selected: p.ID == active})
	}
	// Anthropic model dropdown (always show the stored Anthropic model).
	anthModel := s.aiModelFor(ctx, aiassist.ProviderAnthropic)
	for _, m := range aiModels {
		d.AnthropicModels = append(d.AnthropicModels, aiModelView{ID: m.ID, Label: m.Label, Selected: m.ID == anthModel})
	}
	d.GroqModel = s.aiModelFor(ctx, aiassist.ProviderGroq)
	// Status key per provider.
	ak := s.aiKeyMeta(ctx, aiKeyNameAnthropic)
	d.AnthropicKeyPresent, d.AnthropicKeyUpdated = ak.present, ak.updated
	gk := s.aiKeyMeta(ctx, aiKeyNameGroq)
	d.GroqKeyPresent, d.GroqKeyUpdated = gk.present, gk.updated
	return d
}

func (s *Server) handleAISettings(w http.ResponseWriter, r *http.Request) {
	d := s.aiSettingsData(r)
	if r.URL.Query().Get("saved") == "1" {
		d.Saved = true
	}
	s.render(w, r, "ai", "base", d)
}

func (s *Server) handleAISettingsSave(w http.ResponseWriter, r *http.Request) {
	if s.aistore == nil || s.vault == nil {
		http.Error(w, "the AI feature is not available (store/vault not configured)", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	me, _ := s.currentUser(r)

	// The active provider.
	provider := aiassist.ProviderAnthropic
	if r.FormValue("provider") == string(aiassist.ProviderGroq) {
		provider = aiassist.ProviderGroq
	}
	if err := s.aistore.PutSetting(ctx, aiProviderKey, string(provider)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// The model per provider (store each one if valid; leave it if empty).
	anthModel := strings.TrimSpace(r.FormValue("anthropic_model"))
	if !validAIModel(anthModel) {
		anthModel = defaultModelAnthropic
	}
	if err := s.aistore.PutSetting(ctx, aiModelKeyAnthropic, anthModel); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if gm := strings.TrimSpace(r.FormValue("groq_model")); looksLikeModelID(gm) {
		if err := s.aistore.PutSetting(ctx, aiModelKeyGroq, gm); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// The key per provider — optional: empty = keep the existing one.
	saveKey := func(field, name, label string) bool {
		key := strings.TrimSpace(r.FormValue(field))
		if key == "" {
			return true
		}
		if err := s.vault.Put(ctx, aiSecretScope, name, []byte(key)); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return false
		}
		s.auditAppend(ctx, audit.Event{Kind: "ai.key.set", Allowed: true,
			Message: fmt.Sprintf("%s saved the %s API key (encrypted in the vault)", me, label)})
		return true
	}
	if !saveKey("anthropic_api_key", aiKeyNameAnthropic, "Anthropic") {
		return
	}
	if !saveKey("groq_api_key", aiKeyNameGroq, "Groq") {
		return
	}

	s.auditAppend(ctx, audit.Event{Kind: "ai.config", Allowed: true,
		Message: fmt.Sprintf("%s set the AI provider = %s (model anthropic=%s, groq=%s)", me, provider, anthModel, s.aiModelFor(ctx, aiassist.ProviderGroq))})
	http.Redirect(w, r, "/ai/settings?saved=1", http.StatusSeeOther)
}

func (s *Server) handleAIKeyDelete(w http.ResponseWriter, r *http.Request) {
	if s.vault == nil {
		http.Error(w, "vault not configured", http.StatusServiceUnavailable)
		return
	}
	// Delete the requested provider's key (default anthropic for compatibility).
	provider, label := aiassist.ProviderAnthropic, "Anthropic"
	if r.FormValue("provider") == string(aiassist.ProviderGroq) {
		provider, label = aiassist.ProviderGroq, "Groq"
	}
	_ = s.vault.Delete(r.Context(), aiSecretScope, aiKeyNameFor(provider))
	me, _ := s.currentUser(r)
	s.auditAppend(r.Context(), audit.Event{Kind: "ai.key.delete", Allowed: true,
		Message: fmt.Sprintf("%s deleted the %s API key from the vault", me, label)})
	http.Redirect(w, r, "/ai/settings?saved=1", http.StatusSeeOther)
}

// ---- Per-finding what-if card ----

type aiTargetView struct {
	Method, URL, Parameter, ParamLocation string
}

type aiCardData struct {
	FindingID     string
	CSRF          string
	Ready         bool // AI configured & usable
	NotConfigured bool // show the configuration prompt
	CanConfig     bool // admin user → show the /ai/settings link
	Provider      string
	Model         string
	Target        aiTargetView
	Severity      finding.Severity
	Confidence    string
	OWASP         string
	Engine        string
	SeedHints     []string
	Safety        string
	Analysis      *aiassist.Analysis
	Cached        bool
	GeneratedAt   string
	Err           string
}

func (s *Server) handleAIFinding(w http.ResponseWriter, r *http.Request)      { s.renderAICard(w, r, false) }
func (s *Server) handleAIFindingRegen(w http.ResponseWriter, r *http.Request) { s.renderAICard(w, r, true) }

func (s *Server) renderAICard(w http.ResponseWriter, r *http.Request, force bool) {
	f, err := s.store.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, "finding not found", http.StatusNotFound)
		return
	}
	_, role := s.currentUser(r)
	data := aiCardData{
		FindingID:  f.ID,
		CSRF:       s.csrfToken(r),
		CanConfig:  role == auth.RoleAdmin,
		Severity:   f.Severity,
		Confidence: string(f.Confidence),
		OWASP:      f.OWASP.Label(),
		Engine:     f.SourceEngine,
		SeedHints:  aiassist.SeedHintsFor(f.Type, f.Title),
		Safety:     aiSafetyNote,
		Target: aiTargetView{
			Method: f.Location.Method, URL: f.Location.URL,
			Parameter: f.Location.Parameter, ParamLocation: string(f.Location.ParamLocation),
		},
	}

	if !s.aiReady(r.Context()) {
		data.NotConfigured = true
		s.renderPartial(w, r, "ai", "ai_card", data)
		return
	}
	data.Ready = true
	provider := s.aiProvider(r.Context())
	model := s.aiModel(r.Context())
	data.Model = model
	data.Provider = string(provider)
	in := aiInputFrom(f)
	fp := aiassist.Fingerprint(in)

	if !force {
		if an, at, ok := s.aiCached(r.Context(), f.ID, fp, model); ok {
			data.Analysis, data.Cached, data.GeneratedAt = an, true, at
			s.renderPartial(w, r, "ai", "ai_card", data)
			return
		}
	}

	// One in-flight call per finding; re-check the cache after taking the lock.
	unlock := s.aiLock(f.ID)
	defer unlock()
	if !force {
		if an, at, ok := s.aiCached(r.Context(), f.ID, fp, model); ok {
			data.Analysis, data.Cached, data.GeneratedAt = an, true, at
			s.renderPartial(w, r, "ai", "ai_card", data)
			return
		}
	}

	key, err := s.vault.Reveal(r.Context(), aiSecretScope, aiKeyNameFor(provider))
	if err != nil {
		data.Ready, data.NotConfigured = false, true
		s.renderPartial(w, r, "ai", "ai_card", data)
		return
	}
	an, aerr := aiassist.NewClientFor(provider, model).Analyze(r.Context(), string(key), in)
	for i := range key { // zero the key material as soon as possible
		key[i] = 0
	}
	if aerr != nil {
		data.Err = aerr.Error()
		s.renderPartial(w, r, "ai", "ai_card", data)
		return
	}
	if payload, mErr := json.Marshal(an); mErr == nil {
		_ = s.aistore.PutAIAnalysis(r.Context(), store.AIAnalysis{
			FindingID: f.ID, Program: f.Program, Model: model,
			SourceHash: fp, Payload: string(payload),
		})
	}
	me, _ := s.currentUser(r)
	s.auditAppend(r.Context(), audit.Event{Kind: "ai.analyze", Program: f.Program, Allowed: true,
		Message: fmt.Sprintf("%s generated the AI analysis of finding %s via %s/%s", me, f.ID, provider, model)})
	data.Analysis = &an
	data.GeneratedAt = time.Now().UTC().Format("2006-01-02 15:04Z")
	s.renderPartial(w, r, "ai", "ai_card", data)
}

// aiCached returns a cached analysis that is still valid (hash+model match).
func (s *Server) aiCached(ctx context.Context, id, fp, model string) (*aiassist.Analysis, string, bool) {
	cached, err := s.aistore.GetAIAnalysis(ctx, id)
	if err != nil || cached.SourceHash != fp || cached.Model != model {
		return nil, "", false
	}
	var an aiassist.Analysis
	if json.Unmarshal([]byte(cached.Payload), &an) != nil {
		return nil, "", false
	}
	return &an, cached.CreatedAt.Format("2006-01-02 15:04Z"), true
}
