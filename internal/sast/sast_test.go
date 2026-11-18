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
			t.Errorf("adapter %q must be registered", n)
		}
	}
	if _, ok := Lookup("mock"); !ok {
		t.Error("Lookup of mock failed")
	}
	if _, ok := Lookup("missing"); ok {
		t.Error("Lookup of an unknown adapter must fail")
	}
}

func TestResolveScope(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "src"), 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := Resolve("", "src"); err != ErrDisabled {
		t.Errorf("an empty root must be ErrDisabled; got %v", err)
	}
	got, err := Resolve(root, "src")
	if err != nil {
		t.Fatalf("an in-scope subpath must be ok; got %v", err)
	}
	if filepath.Base(got) != "src" {
		t.Errorf("wrong result path: %s", got)
	}
	if _, err := Resolve(root, filepath.Join("..", "..")); err != ErrOutOfScope {
		t.Errorf("traversal out of the root must be ErrOutOfScope; got %v", err)
	}
	if _, err := Resolve(root, "missing"); err == nil {
		t.Error("a missing path must be an error")
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
		t.Fatalf("there must be 2 new findings; got %d", res.Saved)
	}

	fs, _ := st.List(ctx, store.Query{Program: "demo"})
	if len(fs) != 2 {
		t.Fatalf("the store must have 2 findings; got %d", len(fs))
	}
	for _, f := range fs {
		if f.SourceEngine == "" || f.Severity == "" || f.Location.URL == "" {
			t.Errorf("incomplete SAST finding: %+v", f)
		}
		if f.RunID != "run1" || f.Target != "myrepo" {
			t.Errorf("program/run/target not set by Run: %+v", f)
		}
	}
	if ev, _ := al.List(ctx, audit.Filter{}); len(ev) < 2 {
		t.Errorf("the audit must record start+finish; got %d", len(ev))
	}
}

// TestRunEmptySubpathLabelsTargetDot: an empty subpath (= the whole root) must
// still save findings; the required `target` field gets the label "."
// (regression: it used to be empty → the store rejected every finding with
// "required fields are empty: target").
func TestRunEmptySubpathLabelsTargetDot(t *testing.T) {
	ctx := context.Background()
	st := store.NewMem()
	res, err := Run(ctx, "/whatever", "", "demo", "run1", []Engine{Mock{}}, st, nil)
	if err != nil {
		t.Fatalf("Run with an empty subpath: %v", err)
	}
	if res.Saved == 0 {
		t.Fatal("an empty subpath must still save findings (not 0)")
	}
	fs, _ := st.List(ctx, store.Query{Program: "demo"})
	if len(fs) == 0 {
		t.Fatal("the store is empty after a run with an empty subpath")
	}
	for _, f := range fs {
		if f.Target != "." {
			t.Errorf("Target = %q, want \".\" for an empty subpath", f.Target)
		}
	}
}
