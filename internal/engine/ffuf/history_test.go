package ffuf

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMain: with BH_FAKE_FFUF=1 this test binary stands in for ffuf (fakeFFUF),
// so Scan can be tested end-to-end without a real ffuf and across OSes.
func TestMain(m *testing.M) {
	if os.Getenv("BH_FAKE_FFUF") == "1" {
		fakeFFUF()
		return
	}
	os.Exit(m.Run())
}

// fakeFFUF imitates ffuf v2: it writes the run options (including the -H header)
// to $XDG_CONFIG_HOME/ffuf/history, records that dir (plus a copy of the -w
// wordlist when BH_FAKE_FFUF_WL is set), then writes an empty result to -o.
func fakeFFUF() {
	cfg := os.Getenv("XDG_CONFIG_HOME")
	hist := filepath.Join(cfg, "ffuf", "history", "x")
	_ = os.MkdirAll(hist, 0o750)
	_ = os.WriteFile(filepath.Join(hist, "options"), []byte(strings.Join(os.Args, " ")), 0o640)
	_ = os.WriteFile(os.Getenv("BH_FAKE_FFUF_LOG"), []byte(cfg), 0o600)
	for i := 0; i+1 < len(os.Args); i++ {
		switch os.Args[i] {
		case "-o":
			_ = os.WriteFile(os.Args[i+1], []byte(`{"results":[]}`), 0o600)
		case "-w":
			if wl := os.Getenv("BH_FAKE_FFUF_WL"); wl != "" {
				b, _ := os.ReadFile(os.Args[i+1])
				_ = os.WriteFile(wl, b, 0o600)
			}
		}
	}
	os.Exit(0)
}

// Authenticated scan: logout route entries are dropped from the wordlist (the
// default holds "logout"), since one GET kills the session. Without login the wordlist is intact.
func TestScanDropsLogoutWordsWhenAuth(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	wl := filepath.Join(t.TempDir(), "wl.txt")
	t.Setenv("BH_FAKE_FFUF", "1")
	t.Setenv("BH_FAKE_FFUF_WL", wl)
	for _, auth := range []bool{false, true} {
		r := &Runner{Binary: exe}
		if auth {
			r.UseAuthHeaders([]string{"Cookie: s=1"})
		}
		if _, err := r.Scan(context.Background(), "http://127.0.0.1:1", "p", "r"); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(wl)
		if err != nil {
			t.Fatal(err)
		}
		words := map[string]bool{}
		for _, w := range strings.Fields(string(b)) {
			words[w] = true
		}
		if words["logout"] == auth {
			t.Errorf("auth=%v: logout entry present=%v", auth, words["logout"])
		}
		if !words["login"] || !words["admin"] {
			t.Errorf("auth=%v: non-logout entries must remain", auth)
		}
	}
}

// Secret leak regression (live 2026-11-16): the ffuf history holds the auth
// header value, so it must not land in a shared config home. Each run uses its
// own dir that is removed after the run.
func TestScanFFUFConfigDirPerRun(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	shared := t.TempDir()
	logf := filepath.Join(t.TempDir(), "cfg.txt")
	t.Setenv("XDG_CONFIG_HOME", shared)
	t.Setenv("BH_FAKE_FFUF", "1")
	t.Setenv("BH_FAKE_FFUF_LOG", logf)

	r := &Runner{Binary: exe}
	r.UseAuthHeaders([]string{"Cookie: session=SUPERSECRET"})
	if _, err := r.Scan(context.Background(), "http://127.0.0.1:1", "p", "r1"); err != nil {
		t.Fatal(err)
	}
	cfg, err := os.ReadFile(logf)
	if err != nil || len(cfg) == 0 {
		t.Fatalf("fake ffuf did not run: %v", err)
	}
	if string(cfg) == shared {
		t.Fatal("ffuf still uses the shared config home")
	}
	if _, err := os.Stat(string(cfg)); !os.IsNotExist(err) {
		t.Errorf("the per-run config dir must be removed after the run: %s (%v)", cfg, err)
	}
	if ents, _ := os.ReadDir(shared); len(ents) != 0 {
		t.Errorf("the shared config home must stay empty; found %d entries", len(ents))
	}
}
