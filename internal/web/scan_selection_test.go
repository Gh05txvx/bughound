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
	srv, mu, got, _ := newSelectionServerRPS(t)
	return srv, mu, got
}

// newSelectionServerRPS seperti newSelectionServer tapi juga merekam rps efektif
// yang diterima factory — untuk membuktikan penjepitan laju (mis. stealth).
func newSelectionServerRPS(t *testing.T) (*Server, *sync.Mutex, *Selection, *float64) {
	t.Helper()
	st := store.NewMem()
	k, _ := secret.NewRandomKey()
	var mu sync.Mutex
	got := &Selection{}
	gotRPS := new(float64)
	srv, err := NewServer(Config{
		Store: st,
		NewEngines: func(rps float64, sel Selection) ([]engine.Engine, recon.Engine) {
			mu.Lock()
			*got = sel
			*gotRPS = rps
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
	return srv, &mu, got, gotRPS
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

// Stealth dari form scan harus (a) diteruskan ke engine (sel.Stealth) dan (b)
// menjepit laju scan ke mode low-and-slow, walau rps yang diminta tinggi.
func TestScanStealthThreadedAndClamped(t *testing.T) {
	srv, mu, got, gotRPS := newSelectionServerRPS(t)

	rec := do(t, srv, "POST", "/scan", url.Values{
		"program": {"demo"}, "in_scope": {"demo.test"}, "targets": {"demo.test"},
		"rps":     {"40"}, // tinggi — stealth harus menjepit turun
		"stealth": {"1"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /scan = %d", rec.Code)
	}
	waitRunDone(t, srv, runIDFrom(t, rec.Body.String()))

	mu.Lock()
	defer mu.Unlock()
	if !got.Stealth {
		t.Error("stealth=1 harus diteruskan sebagai sel.Stealth=true")
	}
	if *gotRPS > stealthScanMax {
		t.Errorf("stealth harus menjepit laju ≤ %v; dapat %v", stealthScanMax, *gotRPS)
	}
}

// Tanpa stealth, laju diteruskan apa adanya dan sel.Stealth=false.
func TestScanNoStealthKeepsRate(t *testing.T) {
	srv, mu, got, gotRPS := newSelectionServerRPS(t)

	rec := do(t, srv, "POST", "/scan", url.Values{
		"program": {"demo"}, "in_scope": {"demo.test"}, "targets": {"demo.test"},
		"rps": {"40"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /scan = %d", rec.Code)
	}
	waitRunDone(t, srv, runIDFrom(t, rec.Body.String()))

	mu.Lock()
	defer mu.Unlock()
	if got.Stealth {
		t.Error("tanpa stealth, sel.Stealth harus false")
	}
	if *gotRPS != 40 {
		t.Errorf("tanpa stealth laju harus apa adanya (40); dapat %v", *gotRPS)
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
