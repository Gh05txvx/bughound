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
	aiSecretScope  = "ai"
	aiSecretName   = "api_key"
	aiModelKey     = "ai_model"
	defaultAIModel = "claude-sonnet-5-5"
	aiSafetyNote   = "Non-destruktif saja (boolean/time ringan, baca-saja). Hormati rate-limit & RoE program. Eksekusi MANUAL di Burp Repeater — tanpa auto-submit."
)

// aiModels adalah model Claude yang boleh dipilih. Default = Sonnet (hemat, sesuai
// permintaan pengguna model hemat yang bisa diganti). Opus = penalaran terdalam.
var aiModels = []struct{ ID, Label string }{
	{"claude-sonnet-5-5", "Claude Sonnet 5.5 — seimbang (hemat, default)"},
	{"claude-opus-5-5", "Claude Opus 5.5 — penalaran terdalam (mahal)"},
	{"claude-haiku-5-5", "Claude Haiku 5.5 — paling hemat & cepat"},
}

func validAIModel(m string) bool {
	for _, x := range aiModels {
		if x.ID == m {
			return true
		}
	}
	return false
}

// ---- helper konfigurasi ----

func (s *Server) aiKeyPresent(ctx context.Context) bool {
	if s.vault == nil {
		return false
	}
	metas, err := s.vault.List(ctx, aiSecretScope)
	if err != nil {
		return false
	}
	for _, m := range metas {
		if m.Name == aiSecretName {
			return true
		}
	}
	return false
}

// aiReady melaporkan apakah fitur AI siap dipakai (store mendukung + vault ada +
// key terpasang).
func (s *Server) aiReady(ctx context.Context) bool {
	return s.aistore != nil && s.vault != nil && s.aiKeyPresent(ctx)
}

func (s *Server) aiModel(ctx context.Context) string {
	if s.aistore != nil {
		if m, _ := s.aistore.GetSetting(ctx, aiModelKey); validAIModel(m) {
			return m
		}
	}
	return defaultAIModel
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
	KeyPresent                bool
	KeyUpdated                string
	Model                     string
	Models                    []aiModelView
	Saved                     bool
}

type aiModelView struct {
	ID       string
	Label    string
	Selected bool
}

func (s *Server) aiSettingsData(r *http.Request) aiSettingsData {
	d := aiSettingsData{
		Nav: "ai", Title: "MCP / AI", CSRF: s.csrfToken(r),
		Available: s.aistore != nil && s.vault != nil,
	}
	model := s.aiModel(r.Context())
	d.Model = model
	for _, m := range aiModels {
		d.Models = append(d.Models, aiModelView{ID: m.ID, Label: m.Label, Selected: m.ID == model})
	}
	if s.vault != nil {
		if metas, err := s.vault.List(r.Context(), aiSecretScope); err == nil {
			for _, m := range metas {
				if m.Name == aiSecretName {
					d.KeyPresent = true
					if !m.UpdatedAt.IsZero() {
						d.KeyUpdated = m.UpdatedAt.Format("2006-01-02 15:04Z")
					}
				}
			}
		}
	}
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
	model := strings.TrimSpace(r.FormValue("model"))
	if !validAIModel(model) {
		model = defaultAIModel
	}
	if err := s.aistore.PutSetting(r.Context(), aiModelKey, model); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	me, _ := s.currentUser(r)
	// Key opsional: kosong = pertahankan yang ada (jangan hapus karena form submit model saja).
	if key := strings.TrimSpace(r.FormValue("api_key")); key != "" {
		if err := s.vault.Put(r.Context(), aiSecretScope, aiSecretName, []byte(key)); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.auditAppend(r.Context(), audit.Event{Kind: "ai.key.set", Allowed: true,
			Message: fmt.Sprintf("%s menyimpan API key Claude (terenkripsi di vault)", me)})
	}
	s.auditAppend(r.Context(), audit.Event{Kind: "ai.config", Allowed: true,
		Message: fmt.Sprintf("%s mengatur model AI = %s", me, model)})
	http.Redirect(w, r, "/ai/settings?saved=1", http.StatusSeeOther)
}

func (s *Server) handleAIKeyDelete(w http.ResponseWriter, r *http.Request) {
	if s.vault == nil {
		http.Error(w, "vault tidak dikonfigurasi", http.StatusServiceUnavailable)
		return
	}
	_ = s.vault.Delete(r.Context(), aiSecretScope, aiSecretName)
	me, _ := s.currentUser(r)
	s.auditAppend(r.Context(), audit.Event{Kind: "ai.key.delete", Allowed: true,
		Message: fmt.Sprintf("%s menghapus API key Claude dari vault", me)})
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
	model := s.aiModel(r.Context())
	data.Model = model
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

	key, err := s.vault.Reveal(r.Context(), aiSecretScope, aiSecretName)
	if err != nil {
		data.Ready, data.NotConfigured = false, true
		s.renderPartial(w, r, "ai", "ai_card", data)
		return
	}
	an, aerr := aiassist.NewClient(model).Analyze(r.Context(), string(key), in)
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
		Message: fmt.Sprintf("%s membuat analisis AI temuan %s via %s", me, f.ID, model)})
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
