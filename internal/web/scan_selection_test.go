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

// newSelectionServer builds a server with NewEngines that RECORDS the Selection
// received per run — to prove the template selection from the scan form is
// really passed to the engine execution path (not just the UI).
func newSelectionServer(t *testing.T) (*Server, *sync.Mutex, *Selection) {
	srv, mu, got, _ := newSelectionServerRPS(t)
	return srv, mu, got
}

// newSelectionServerRPS is like newSelectionServer but also records the effective rps
// the factory receives — to prove the rate clamp (e.g. stealth).
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
		"tags":     {"cve, exposure"},             // comma/space separated
		"severity": {"critical", "high", "bogus"}, // bogus must be filtered out
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /scan = %d", rec.Code)
	}
	waitRunDone(t, srv, runIDFrom(t, rec.Body.String()))

	mu.Lock()
	defer mu.Unlock()
	if want := []string{"cve", "exposure"}; !eqStr(got.Tags, want) {
		t.Errorf("tags passed = %v, want %v", got.Tags, want)
	}
	if want := []string{"critical", "high"}; !eqStr(got.Severity, want) {
		t.Errorf("severity passed = %v, want %v (bogus must be filtered out)", got.Severity, want)
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
		t.Errorf("an empty selection must stay empty (all templates), got tags=%v severity=%v", got.Tags, got.Severity)
	}
}

// Stealth from the scan form must (a) pass through to the engine (sel.Stealth) and (b)
// clamp the scan rate to low-and-slow mode, even if the requested rps is high.
func TestScanStealthThreadedAndClamped(t *testing.T) {
	srv, mu, got, gotRPS := newSelectionServerRPS(t)

	rec := do(t, srv, "POST", "/scan", url.Values{
		"program": {"demo"}, "in_scope": {"demo.test"}, "targets": {"demo.test"},
		"rps":     {"40"}, // high — stealth must clamp it down
		"stealth": {"1"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /scan = %d", rec.Code)
	}
	waitRunDone(t, srv, runIDFrom(t, rec.Body.String()))

	mu.Lock()
	defer mu.Unlock()
	if !got.Stealth {
		t.Error("stealth=1 must pass through as sel.Stealth=true")
	}
	if *gotRPS > stealthScanMax {
		t.Errorf("stealth must clamp the rate ≤ %v; got %v", stealthScanMax, *gotRPS)
	}
}

// Without stealth, the rate passes through as-is and sel.Stealth=false.
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
		t.Error("without stealth, sel.Stealth must be false")
	}
	if *gotRPS != 40 {
		t.Errorf("without stealth the rate must be as-is (40); got %v", *gotRPS)
	}
}

// api_routes from the scan form must pass through to the engine (sel.APIRoutes), and
// default off when not ticked (opt-in, large volume).
func TestScanAPIRoutesThreaded(t *testing.T) {
	srv, mu, got := newSelectionServer(t)

	rec := do(t, srv, "POST", "/scan", url.Values{
		"program": {"demo"}, "in_scope": {"demo.test"}, "targets": {"demo.test"},
		"api_routes": {"1"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /scan = %d", rec.Code)
	}
	waitRunDone(t, srv, runIDFrom(t, rec.Body.String()))

	mu.Lock()
	if !got.APIRoutes {
		t.Error("api_routes=1 must pass through as sel.APIRoutes=true")
	}
	mu.Unlock()

	// Without the tick → false.
	rec = do(t, srv, "POST", "/scan", url.Values{
		"program": {"demo"}, "in_scope": {"demo.test"}, "targets": {"demo.test"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /scan (without api_routes) = %d", rec.Code)
	}
	waitRunDone(t, srv, runIDFrom(t, rec.Body.String()))
	mu.Lock()
	defer mu.Unlock()
	if got.APIRoutes {
		t.Error("without api_routes, sel.APIRoutes must be false (opt-in)")
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
