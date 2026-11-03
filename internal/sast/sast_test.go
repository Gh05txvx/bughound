package sast

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"bughound/internal/audit"
	"bughound/internal/store"
)

func TestRegistryHasAdapters(t *testing.T) {
	want := map[string]bool{"mock": false, "semgrep": false}
	for _, n := range Names() {
		if _, ok := want[n]; ok {
			want[n] = true
		}
	}
	for n, found := range want {
		if !found {
			t.Errorf("adapter %q harus terdaftar", n)
		}
	}
	if _, ok := Lookup("mock"); !ok {
		t.Error("Lookup mock gagal")
	}
	if _, ok := Lookup("tak-ada"); ok {
		t.Error("Lookup adapter tak dikenal harus gagal")
	}
}

func TestResolveScope(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "src"), 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := Resolve("", "src"); err != ErrDisabled {
		t.Errorf("root kosong harus ErrDisabled; dapat %v", err)
	}
	got, err := Resolve(root, "src")
	if err != nil {
		t.Fatalf("subpath in-scope harus ok; dapat %v", err)
	}
	if filepath.Base(got) != "src" {
		t.Errorf("path hasil salah: %s", got)
	}
	if _, err := Resolve(root, filepath.Join("..", "..")); err != ErrOutOfScope {
		t.Errorf("traversal keluar root harus ErrOutOfScope; dapat %v", err)
	}
	if _, err := Resolve(root, "tak-ada"); err == nil {
		t.Error("path tak ada harus error")
	}
}

func TestRunStoresMockFindings(t *testing.T) {
	ctx := context.Background()
	st := store.NewMem()
	al := audit.NewMemLog([]byte("k"))
	dir, err := Resolve(t.TempDir(), ".")
	if err != nil {
		t.Fatal(err)
	}

	res, err := Run(ctx, dir, "myrepo", "demo", "run1", []Engine{Mock{}}, st, al)
	if err != nil {
		t.Fatal(err)
	}
	if res.Saved != 2 {
		t.Fatalf("harus 2 temuan baru; dapat %d", res.Saved)
	}

	fs, _ := st.List(ctx, store.Query{Program: "demo"})
	if len(fs) != 2 {
		t.Fatalf("store harus punya 2 temuan; dapat %d", len(fs))
	}
	for _, f := range fs {
		if f.SourceEngine == "" || f.Severity == "" || f.Location.URL == "" {
			t.Errorf("temuan SAST tak lengkap: %+v", f)
		}
		if f.RunID != "run1" || f.Target != "myrepo" {
			t.Errorf("program/run/target tak di-set oleh Run: %+v", f)
		}
	}
	if ev, _ := al.List(ctx, audit.Filter{}); len(ev) < 2 {
		t.Errorf("audit harus mencatat start+finish; dapat %d", len(ev))
	}
}

// TestRunEmptySubpathLabelsTargetDot: subpath kosong (= seluruh root) harus
// tetap menyimpan temuan; field wajib `target` diberi label "." (regresi: dulu
// kosong → store menolak semua temuan dengan "field wajib kosong: target").
func TestRunEmptySubpathLabelsTargetDot(t *testing.T) {
	ctx := context.Background()
	st := store.NewMem()
	res, err := Run(ctx, "/whatever", "", "demo", "run1", []Engine{Mock{}}, st, nil)
	if err != nil {
		t.Fatalf("Run subpath kosong: %v", err)
	}
	if res.Saved == 0 {
		t.Fatal("subpath kosong harus tetap menyimpan temuan (bukan 0)")
	}
	fs, _ := st.List(ctx, store.Query{Program: "demo"})
	if len(fs) == 0 {
		t.Fatal("store kosong setelah run subpath kosong")
	}
	for _, f := range fs {
		if f.Target != "." {
			t.Errorf("Target = %q, ingin \".\" untuk subpath kosong", f.Target)
		}
	}
}
