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
	if got := engineLabel([]engine.Engine{nuclei.Mock{}, ffuf.Mock{}}); got != "engine: mock (no network)" {
		t.Errorf("engine mock: %q", got)
	}
	// A real Runner (ProxyAware) is only built, not run: no network.
	if got := engineLabel([]engine.Engine{&nuclei.Runner{}, &ffuf.Runner{}}); got != "engine: real (nuclei, ffuf)" {
		t.Errorf("real engine: %q", got)
	}
}

func TestReconLabel(t *testing.T) {
	if got := reconLabel(nil); !strings.Contains(got, "not active") {
		t.Errorf("recon nil: %q", got)
	}
	if got := reconLabel(recon.MockPipeline{}); got != "recon mock, no network: subfinder→httpx→katana, the results are still filtered by the scope guard" {
		t.Errorf("recon mock: %q", got)
	}
	// A real pipeline (ProxyAware) is only built, not run: no network.
	if got := reconLabel(recon.NewRealPipelineRate(1)); got != "recon real: subfinder/gau→dnsx→httpx→naabu/katana, the results are still filtered by the scope guard" {
		t.Errorf("real recon: %q", got)
	}
}

// newRealModeServer builds a server with real engines & recon that are only
// built, never run (no scan): enough to test the UI label.
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
	if b := do(t, mock, "GET", "/dashboard", nil).Body.String(); !strings.Contains(b, "engine: mock (no network)") {
		t.Error("the sidebar in mock mode must be labeled mock")
	}
	b := do(t, newRealModeServer(t), "GET", "/dashboard", nil).Body.String()
	if !strings.Contains(b, "engine: real (nuclei)") || strings.Contains(b, "no network") {
		t.Error("the sidebar in real mode must not be labeled mock")
	}
}

func TestScanFormShowsActualReconMode(t *testing.T) {
	mock, _ := newTestServer(t)
	if b := do(t, mock, "GET", "/scan", nil).Body.String(); !strings.Contains(b, "recon mock, no network: subfinder→httpx→katana") {
		t.Error("the scan form in mock mode must be labeled recon mock")
	}
	b := do(t, newRealModeServer(t), "GET", "/scan", nil).Body.String()
	if !strings.Contains(b, "recon real: subfinder/gau→dnsx→httpx→naabu/katana") || strings.Contains(b, "recon mock") {
		t.Error("the scan form in real mode must not be labeled mock")
	}
}
