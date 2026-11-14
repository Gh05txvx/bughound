package web

// Integrasi MCP/AI: menu web untuk memasukkan API key Claude (disimpan di vault
// terenkripsi) + kartu what-if per temuan yang dihasilkan Claude API dan di-cache.
//
// Batas keamanan (prinsip mengikat BugHound):
//   - API key = secret: via vault terenkripsi (scope "ai"), teredaksi, tak pernah
//     ke log/report/commit, akses ter-audit otomatis oleh reveal-hook vault.
//   - Egress ke api.anthropic.com = kontrol-plane opt-in + ter-audit, TERPISAH dari
//     scope guard/proxy scan (lihat internal/aiassist). Hanya aktif bila key diisi.
//   - Evidence discrub sebelum dikirim (aiassist.ScrubText).
//   - Advisory: kartu = rencana validasi manual; eksekusi Burp tetap manual, tanpa
//     auto-submit.

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
	// Nama secret vault per provider. Anthropic memakai "api_key" (DIPERTAHANKAN
	// agar key lama tetap terbaca); Groq terpisah agar keduanya bisa tersimpan.
	aiKeyNameAnthropic = "api_key"
	aiKeyNameGroq      = "groq_api_key"

	aiProviderKey = "ai_provider" // setelan: provider aktif ("anthropic"|"groq")
	// Setelan model per provider (terpisah agar ganti provider tak saling menimpa).
	aiModelKeyAnthropic = "ai_model"      // DIPERTAHANKAN (backward-compat)
	aiModelKeyGroq      = "ai_model_groq" // Groq model = teks bebas (ID cepat berubah)

	defaultModelAnthropic = "claude-sonnet-5-5"
	defaultModelGroq      = "openai/gpt-oss-20b" // default masuk akal; dapat diganti (ID Groq sering berubah)

	aiSafetyNote = "Non-destruktif saja (boolean/time ringan, baca-saja). Hormati rate-limit & RoE program. Eksekusi MANUAL di Burp Repeater — tanpa auto-submit."
)

// aiModels adalah model Claude yang boleh dipilih (whitelist; ID Anthropic stabil).
// Default = Sonnet (hemat, bisa diganti). Opus = penalaran terdalam.
var aiModels = []struct{ ID, Label string }{
	{"claude-sonnet-5-5", "Claude Sonnet 5.5 — seimbang (hemat, default)"},
	{"claude-opus-5-5", "Claude Opus 5.5 — penalaran terdalam (mahal)"},
	{"claude-haiku-5-5", "Claude Haiku 5.5 — paling hemat & cepat"},
}

// aiProviders = daftar provider yang dapat dipilih di setelan.
var aiProviders = []struct {
	ID    aiassist.Provider
	Label string
}{
	{aiassist.ProviderAnthropic, "Anthropic (Claude) — berbayar, kualitas tinggi"},
	{aiassist.ProviderGroq, "Groq — free-tier, model open (Llama/GPT-OSS), sangat cepat"},
}

func validAIModel(m string) bool {
	for _, x := range aiModels {
		if x.ID == m {
			return true
		}
	}
	return false
}

// looksLikeModelID menjaga model Groq (teks bebas) ke charset ID yang wajar —
// huruf/angka/`-._/:` (mis. "openai/gpt-oss-20b", "llama-3.3-70b-versatile").
// Mencegah injeksi/noise; ID yang sudah pensiun akan ditolak Groq dgn pesan jelas.
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

// aiProvider mengembalikan provider aktif dari setelan (default anthropic).
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

// validModelFor memvalidasi model sesuai provider: whitelist utk Anthropic,
// charset ID bebas utk Groq (daftarnya cepat berubah).
func validModelFor(p aiassist.Provider, m string) bool {
	if p == aiassist.ProviderGroq {
		return looksLikeModelID(m)
	}
	return validAIModel(m)
}

// ---- helper konfigurasi ----

// aiKeyPresent melapor apakah key provider AKTIF terpasang.
func (s *Server) aiKeyPresent(ctx context.Context) bool {
	return s.aiKeyMeta(ctx, aiKeyNameFor(s.aiProvider(ctx))).present
}

type aiKeyMeta struct {
	present bool
	updated string
}

// aiKeyMeta mencari status satu secret (per nama) di vault scope "ai".
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

// aiReady melaporkan apakah fitur AI siap dipakai (store mendukung + vault ada +
// key terpasang).
func (s *Server) aiReady(ctx context.Context) bool {
	return s.aistore != nil && s.vault != nil && s.aiKeyPresent(ctx)
}

// aiModel mengembalikan model untuk provider AKTIF (validasi per provider).
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

// aiLock memberi satu lock per temuan agar dua pembukaan bersamaan tak memicu dua
// panggilan Claude (hindari double-bill).
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

// ---- Halaman setelan MCP/AI ----

type aiSettingsData struct {
	Nav, Title, Program, CSRF string // Program dipakai base.html (nav) — selalu kosong di sini
	Available                 bool   // store+vault mendukung
	Provider                  string // provider aktif ("anthropic"|"groq")
	Providers                 []aiProviderView
	// Anthropic (model = dropdown whitelist)
	AnthropicKeyPresent bool
	AnthropicKeyUpdated string
	AnthropicModels     []aiModelView
	// Groq (model = teks bebas; ID cepat berubah)
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
	// Anthropic model dropdown (selalu tunjukkan model Anthropic tersimpan).
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
		http.Error(w, "fitur AI tak tersedia (store/vault tidak dikonfigurasi)", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form tidak valid", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	me, _ := s.currentUser(r)

	// Provider aktif.
	provider := aiassist.ProviderAnthropic
	if r.FormValue("provider") == string(aiassist.ProviderGroq) {
		provider = aiassist.ProviderGroq
	}
	if err := s.aistore.PutSetting(ctx, aiProviderKey, string(provider)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Model per provider (simpan masing-masing bila valid; biarkan jika kosong).
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

	// Key per provider — opsional: kosong = pertahankan yang ada.
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
			Message: fmt.Sprintf("%s menyimpan API key %s (terenkripsi di vault)", me, label)})
		return true
	}
	if !saveKey("anthropic_api_key", aiKeyNameAnthropic, "Anthropic") {
		return
	}
	if !saveKey("groq_api_key", aiKeyNameGroq, "Groq") {
		return
	}

	s.auditAppend(ctx, audit.Event{Kind: "ai.config", Allowed: true,
		Message: fmt.Sprintf("%s mengatur provider AI = %s (model anthropic=%s, groq=%s)", me, provider, anthModel, s.aiModelFor(ctx, aiassist.ProviderGroq))})
	http.Redirect(w, r, "/ai/settings?saved=1", http.StatusSeeOther)
}

func (s *Server) handleAIKeyDelete(w http.ResponseWriter, r *http.Request) {
	if s.vault == nil {
		http.Error(w, "vault tidak dikonfigurasi", http.StatusServiceUnavailable)
		return
	}
	// Hapus key provider yang diminta (default anthropic untuk kompatibilitas).
	provider, label := aiassist.ProviderAnthropic, "Anthropic"
	if r.FormValue("provider") == string(aiassist.ProviderGroq) {
		provider, label = aiassist.ProviderGroq, "Groq"
	}
	_ = s.vault.Delete(r.Context(), aiSecretScope, aiKeyNameFor(provider))
	me, _ := s.currentUser(r)
	s.auditAppend(r.Context(), audit.Event{Kind: "ai.key.delete", Allowed: true,
		Message: fmt.Sprintf("%s menghapus API key %s dari vault", me, label)})
	http.Redirect(w, r, "/ai/settings?saved=1", http.StatusSeeOther)
}

// ---- Kartu what-if per temuan ----

type aiTargetView struct {
	Method, URL, Parameter, ParamLocation string
}

type aiCardData struct {
	FindingID     string
	CSRF          string
	Ready         bool // AI terkonfigurasi & bisa dipakai
	NotConfigured bool // tampilkan ajakan konfigurasi
	CanConfig     bool // pengguna admin → tampilkan tautan /ai/settings
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
		http.Error(w, "temuan tidak ditemukan", http.StatusNotFound)
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

	// Satu panggilan in-flight per temuan; re-cek cache setelah dapat lock.
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
	for i := range key { // nolkan material key secepatnya
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
		Message: fmt.Sprintf("%s membuat analisis AI temuan %s via %s/%s", me, f.ID, provider, model)})
	data.Analysis = &an
	data.GeneratedAt = time.Now().UTC().Format("2006-01-02 15:04Z")
	s.renderPartial(w, r, "ai", "ai_card", data)
}

// aiCached mengembalikan analisis cache yang masih valid (hash+model cocok).
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
