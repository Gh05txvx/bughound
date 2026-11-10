package web

import (
	"strings"
	"testing"

	"bughound/internal/audit"
	"bughound/internal/engine"
	"bughound/internal/engine/ffuf"
	"bughound/internal/engine/nuclei"
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

func TestSidebarShowsActualEngineMode(t *testing.T) {
	mock, _ := newTestServer(t)
	if b := do(t, mock, "GET", "/dashboard", nil).Body.String(); !strings.Contains(b, "engine: mock (tanpa jaringan)") {
		t.Error("sidebar mode mock harus berlabel mock")
	}

	k, _ := secret.NewRandomKey()
	real, err := NewServer(Config{
		Store:        store.NewMem(),
		Engines:      []engine.Engine{&nuclei.Runner{}},
		Vault:        secret.NewMemVault(secret.NewKeyring(k)),
		Audit:        audit.NewMemLog([]byte("k")),
		AuthDisabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { real.Close() })
	b := do(t, real, "GET", "/dashboard", nil).Body.String()
	if !strings.Contains(b, "engine: nyata (nuclei)") || strings.Contains(b, "tanpa jaringan") {
		t.Error("sidebar mode nyata tak boleh berlabel mock")
	}
}
