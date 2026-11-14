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
		Type: "sqli", Title: "SQLi di q", SourceEngine: "nuclei",
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
	if body := rec.Body.String(); !strings.Contains(body, "belum diaktifkan") {
		t.Fatalf("tak menampilkan ajakan konfigurasi:\n%s", body)
	}
}

// TestAICard_ServesFromCacheNoNetwork membuktikan cache mencegah panggilan Claude
// API (bila tidak, Reveal+HTTP ke endpoint nyata akan terjadi). Key dipasang agar
// aiReady, tapi cache yang cocok harus short-circuit sebelum reveal/jaringan.
func TestAICard_ServesFromCacheNoNetwork(t *testing.T) {
	srv, st := newAIServer(t)
	f := saveAITestFinding(t, st)
	if err := srv.vault.Put(context.Background(), aiSecretScope, aiKeyNameAnthropic, []byte("sk-test")); err != nil {
		t.Fatal(err)
	}
	fp := aiassist.Fingerprint(aiInputFrom(f))
	_ = st.PutAIAnalysis(context.Background(), store.AIAnalysis{
		FindingID: f.ID, Program: f.Program, Model: defaultModelAnthropic, SourceHash: fp,
		Payload: `{"why":"karena refleksi","decision":"verify_now","hypotheses":[{"mutation":"q=1'","expected":"error SQL","confirms":"SQLi"}]}`,
	})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/ai/finding/"+f.ID, nil))
	body := rec.Body.String()
	for _, want := range []string{"verifikasi sekarang", "q=1&#39;", "dari cache"} {
		if !strings.Contains(body, want) {
			t.Fatalf("kartu cache tak memuat %q:\n%s", want, body)
		}
	}
}

// TestAICard_ErrorPathRenders menjaga agar kartu saat GENERATE GAGAL (Err terisi,
// Analysis nil) tetap dirender rapi, bukan meledak di template. Baris
// {{if and .Analysis (not .Analysis.Hypotheses)}} harus aman saat Analysis nil.
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
		t.Fatalf("render jalur-error gagal (template meledak saat Analysis nil): %v", err)
	}
	if !strings.Contains(buf.String(), "boom-network") {
		t.Fatalf("pesan error tak tampil:\n%s", buf.String())
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
		t.Fatalf("form setelan AI tak dirender:\n%s", rec.Body.String())
	}
}

// TestAISettings_RendersBothProviders memastikan halaman setelan menampilkan
// pemilih provider + kedua blok (Anthropic & Groq), bukan hanya Anthropic.
func TestAISettings_RendersBothProviders(t *testing.T) {
	srv, _ := newAIServer(t)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/ai/settings", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("code %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"Provider aktif", "Anthropic (Claude)", "API key Groq", defaultModelGroq} {
		if !strings.Contains(body, want) {
			t.Fatalf("setelan tak memuat %q:\n%s", want, body)
		}
	}
}

// TestAISettings_SaveSelectsGroq menyimpan Groq sebagai provider aktif lewat
// handler (CSRF double-submit) lalu memverifikasi provider/model aktif + key
// Groq tersimpan, dan model Anthropic tetap terpisah (tak tertimpa).
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
		t.Fatalf("simpan = %d, mau 303; body: %s", rec.Code, rec.Body.String())
	}
	ctx := context.Background()
	if p := srv.aiProvider(ctx); p != aiassist.ProviderGroq {
		t.Fatalf("provider aktif = %q, mau groq", p)
	}
	if m := srv.aiModel(ctx); m != "openai/gpt-oss-120b" {
		t.Fatalf("model groq aktif = %q, mau openai/gpt-oss-120b", m)
	}
	if !srv.aiKeyPresent(ctx) {
		t.Fatal("key groq (provider aktif) harus terpasang setelah simpan")
	}
	// Model Anthropic disimpan terpisah, tak tertimpa oleh pilihan Groq.
	if m := srv.aiModelFor(ctx, aiassist.ProviderAnthropic); m != "claude-haiku-5-5" {
		t.Fatalf("model anthropic = %q, mau claude-haiku-5-5", m)
	}
}

// TestAI_ActiveProviderKeyGating membuktikan aiReady mengikuti key provider
// AKTIF: memilih Groq tanpa key Groq → belum siap meski key Anthropic ada;
// model jatuh ke default Groq sampai di-set.
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
		t.Fatal("provider aktif harus groq")
	}
	if srv.aiReady(ctx) {
		t.Fatal("tanpa key groq, provider groq tak boleh ready (key anthropic tak menghitung)")
	}
	if m := srv.aiModel(ctx); m != defaultModelGroq {
		t.Fatalf("model groq default = %q, mau %q", m, defaultModelGroq)
	}
	if err := srv.vault.Put(ctx, aiSecretScope, aiKeyNameGroq, []byte("gsk-test")); err != nil {
		t.Fatal(err)
	}
	if !srv.aiReady(ctx) {
		t.Fatal("dengan key groq, provider groq harus ready")
	}
}
