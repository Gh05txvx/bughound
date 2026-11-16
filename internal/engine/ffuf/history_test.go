package ffuf

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMain: dengan BH_FAKE_FFUF=1 binary tes ini menyamar sebagai ffuf (fakeFFUF),
// agar Scan bisa diuji end-to-end tanpa ffuf asli & lintas OS.
func TestMain(m *testing.M) {
	if os.Getenv("BH_FAKE_FFUF") == "1" {
		fakeFFUF()
		return
	}
	os.Exit(m.Run())
}

// fakeFFUF meniru ffuf v2: menulis opsi run (termasuk header -H) ke
// $XDG_CONFIG_HOME/ffuf/history, mencatat dir itu, lalu hasil kosong ke -o.
func fakeFFUF() {
	cfg := os.Getenv("XDG_CONFIG_HOME")
	hist := filepath.Join(cfg, "ffuf", "history", "x")
	_ = os.MkdirAll(hist, 0o750)
	_ = os.WriteFile(filepath.Join(hist, "options"), []byte(strings.Join(os.Args, " ")), 0o640)
	_ = os.WriteFile(os.Getenv("BH_FAKE_FFUF_LOG"), []byte(cfg), 0o600)
	for i, a := range os.Args {
		if a == "-o" && i+1 < len(os.Args) {
			_ = os.WriteFile(os.Args[i+1], []byte(`{"results":[]}`), 0o600)
		}
	}
	os.Exit(0)
}

// Regresi kebocoran secret (live 2026-11-16): history ffuf memuat nilai header
// auth, jadi tak boleh jatuh ke config home bersama — tiap run memakai dir
// sendiri yang dihapus selepas run.
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
		t.Fatalf("ffuf palsu tak dijalankan: %v", err)
	}
	if string(cfg) == shared {
		t.Fatal("ffuf masih memakai config home bersama")
	}
	if _, err := os.Stat(string(cfg)); !os.IsNotExist(err) {
		t.Errorf("dir konfigurasi per run harus dihapus selepas run: %s (%v)", cfg, err)
	}
	if ents, _ := os.ReadDir(shared); len(ents) != 0 {
		t.Errorf("config home bersama harus tetap kosong; ada %d entri", len(ents))
	}
}
