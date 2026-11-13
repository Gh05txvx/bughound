package web

import (
	"context"
	"net/http"
	"net/http/httptest"
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
	if err := srv.vault.Put(context.Background(), aiSecretScope, aiSecretName, []byte("sk-test")); err != nil {
		t.Fatal(err)
	}
	fp := aiassist.Fingerprint(aiInputFrom(f))
	_ = st.PutAIAnalysis(context.Background(), store.AIAnalysis{
		FindingID: f.ID, Program: f.Program, Model: defaultAIModel, SourceHash: fp,
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
