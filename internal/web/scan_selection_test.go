package web

import (
	"net/http"
	"net/url"
	"sync"
	"testing"

	"bughound/internal/audit"
	"bughound/internal/engine"
	"bughound/internal/engine/nuclei"
	"bughound/internal/recon"
	"bughound/internal/secret"
	"bughound/internal/store"
)

// newSelectionServer membangun server dengan NewEngines yang MEREKAM Selection
// yang diterima tiap run — untuk membuktikan seleksi template dari form scan
// benar-benar diteruskan ke jalur eksekusi engine (bukan sekadar UI).
func newSelectionServer(t *testing.T) (*Server, *sync.Mutex, *Selection) {
	t.Helper()
	st := store.NewMem()
	k, _ := secret.NewRandomKey()
	var mu sync.Mutex
	got := &Selection{}
	srv, err := NewServer(Config{
		Store: st,
		NewEngines: func(rps float64, sel Selection) ([]engine.Engine, recon.Engine) {
			mu.Lock()
			*got = sel
			mu.Unlock()
			return []engine.Engine{nuclei.Mock{}}, nil
		},
		Engines:      []engine.Engine{nuclei.Mock{}},
		Vault:        secret.NewMemVault(secret.NewKeyring(k)),
		Audit:        audit.NewMemLog([]byte("test-audit-key")),
		AuthDisabled: true,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv, &mu, got
}

func TestScanSelectionThreadedToEngines(t *testing.T) {
	srv, mu, got := newSelectionServer(t)

	rec := do(t, srv, "POST", "/scan", url.Values{
		"program":  {"demo"},
		"in_scope": {"demo.test"},
		"targets":  {"demo.test"},
		"tags":     {"cve, exposure"},             // dipisah koma/spasi
		"severity": {"critical", "high", "bogus"}, // bogus harus tersaring
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /scan = %d", rec.Code)
	}
	waitRunDone(t, srv, runIDFrom(t, rec.Body.String()))

	mu.Lock()
	defer mu.Unlock()
	if want := []string{"cve", "exposure"}; !eqStr(got.Tags, want) {
		t.Errorf("tags diteruskan = %v, ingin %v", got.Tags, want)
	}
	if want := []string{"critical", "high"}; !eqStr(got.Severity, want) {
		t.Errorf("severity diteruskan = %v, ingin %v (bogus harus tersaring)", got.Severity, want)
	}
}

func TestScanSelectionEmptyMeansAll(t *testing.T) {
	srv, mu, got := newSelectionServer(t)

	rec := do(t, srv, "POST", "/scan", url.Values{
		"program": {"demo"}, "in_scope": {"demo.test"}, "targets": {"demo.test"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /scan = %d", rec.Code)
	}
	waitRunDone(t, srv, runIDFrom(t, rec.Body.String()))

	mu.Lock()
	defer mu.Unlock()
	if len(got.Tags) != 0 || len(got.Severity) != 0 {
		t.Errorf("seleksi kosong harus tetap kosong (semua template), dapat tags=%v severity=%v", got.Tags, got.Severity)
	}
}

func eqStr(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
