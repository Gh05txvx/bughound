package web

import (
	"strings"
	"testing"

	"bughound/internal/audit"
	"bughound/internal/engine"
	"bughound/internal/engine/ffuf"
	"bughound/internal/engine/nuclei"
	"bughound/internal/recon"
	"bughound/internal/secret"
	"bughound/internal/store"
)

func TestEngineLabel(t *testing.T) {
	if got := engineLabel([]engine.Engine{nuclei.Mock{}, ffuf.Mock{}}); got != "engine: mock (tanpa jaringan)" {
		t.Errorf("engine mock: %q", got)
	}
	// Runner nyata (ProxyAware) cukup dibuat, tak dijalankan: tanpa jaringan.
	if got := engineLabel([]engine.Engine{&nuclei.Runner{}, &ffuf.Runner{}}); got != "engine: nyata (nuclei, ffuf)" {
		t.Errorf("engine nyata: %q", got)
	}
}

func TestReconLabel(t *testing.T) {
	if got := reconLabel(nil); !strings.Contains(got, "tidak aktif") {
		t.Errorf("recon nil: %q", got)
	}
	if got := reconLabel(recon.MockPipeline{}); got != "recon mock, tanpa jaringan: subfinder→httpx→katana — hasilnya tetap disaring scope guard" {
		t.Errorf("recon mock: %q", got)
	}
	// Pipeline nyata (ProxyAware) cukup dibuat, tak dijalankan: tanpa jaringan.
	if got := reconLabel(recon.NewRealPipelineRate(1)); got != "recon nyata: subfinder/gau→dnsx→httpx→naabu/katana — hasilnya tetap disaring scope guard" {
		t.Errorf("recon nyata: %q", got)
	}
}

// newRealModeServer membangun server dengan engine & recon nyata yang hanya
// dibuat, tak pernah dijalankan (tak ada scan): cukup untuk menguji label UI.
func newRealModeServer(t *testing.T) *Server {
	t.Helper()
	k, _ := secret.NewRandomKey()
	s, err := NewServer(Config{
		Store:        store.NewMem(),
		Engines:      []engine.Engine{&nuclei.Runner{}},
		Recon:        recon.NewRealPipelineRate(1),
		Vault:        secret.NewMemVault(secret.NewKeyring(k)),
		Audit:        audit.NewMemLog([]byte("k")),
		AuthDisabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestSidebarShowsActualEngineMode(t *testing.T) {
	mock, _ := newTestServer(t)
	if b := do(t, mock, "GET", "/dashboard", nil).Body.String(); !strings.Contains(b, "engine: mock (tanpa jaringan)") {
		t.Error("sidebar mode mock harus berlabel mock")
	}
	b := do(t, newRealModeServer(t), "GET", "/dashboard", nil).Body.String()
	if !strings.Contains(b, "engine: nyata (nuclei)") || strings.Contains(b, "tanpa jaringan") {
		t.Error("sidebar mode nyata tak boleh berlabel mock")
	}
}

func TestScanFormShowsActualReconMode(t *testing.T) {
	mock, _ := newTestServer(t)
	if b := do(t, mock, "GET", "/scan", nil).Body.String(); !strings.Contains(b, "recon mock, tanpa jaringan: subfinder→httpx→katana") {
		t.Error("form scan mode mock harus berlabel recon mock")
	}
	b := do(t, newRealModeServer(t), "GET", "/scan", nil).Body.String()
	if !strings.Contains(b, "recon nyata: subfinder/gau→dnsx→httpx→naabu/katana") || strings.Contains(b, "recon mock") {
		t.Error("form scan mode nyata tak boleh berlabel mock")
	}
}
