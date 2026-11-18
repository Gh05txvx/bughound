package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"bughound/internal/finding"
)

func openTemp(t *testing.T) *SQLite {
	t.Helper()
	s, err := OpenSQLite(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestSQLiteSaveAndGet(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	f := mkFinding("acme", "run1", "ssrf", "https://acme.io", "https://acme.io/fetch", "url", finding.SeverityCritical)
	res, err := s.Save(ctx, f)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if res.ID == "" || res.Deduplicated {
		t.Fatalf("unexpected Save result: %+v", res)
	}
	got, err := s.Get(ctx, res.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Type != "ssrf" || got.Severity != finding.SeverityCritical || got.DedupKey == "" {
		t.Errorf("the stored finding does not match: %+v", got)
	}
	if _, err := s.Get(ctx, "missing"); err != ErrNotFound {
		t.Errorf("a missing id must be ErrNotFound, got %v", err)
	}
}

func TestSQLiteDedup(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	a := mkFinding("acme", "run1", "xss", "https://acme.io", "https://acme.io/s?q=1", "q", finding.SeverityHigh)
	b := mkFinding("acme", "run2", "xss", "https://acme.io", "https://acme.io/s?q=zz", "q", finding.SeverityHigh)
	ra, _ := s.Save(ctx, a)
	rb, _ := s.Save(ctx, b)
	if ra.Deduplicated {
		t.Fatal("a must become the primary")
	}
	if !rb.Deduplicated || rb.PrimaryID != ra.ID {
		t.Fatalf("b must be a duplicate of a: %+v", rb)
	}
	got, _ := s.Get(ctx, rb.ID)
	if got.Status != finding.StatusDuplicate || got.DuplicateOf != ra.ID {
		t.Errorf("b: status=%s duplicate_of=%s", got.Status, got.DuplicateOf)
	}
}

func TestSQLiteDedupPerProgram(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	ra, _ := s.Save(ctx, mkFinding("prog-a", "r", "ssrf", "https://acme.io", "https://acme.io/x", "p", finding.SeverityLow))
	rb, _ := s.Save(ctx, mkFinding("prog-b", "r", "ssrf", "https://acme.io", "https://acme.io/x", "p", finding.SeverityLow))
	if ra.Deduplicated || rb.Deduplicated {
		t.Error("the same dedup_key in different programs must not duplicate each other")
	}
}

func TestSQLiteListFilterAndSort(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	s.Save(ctx, mkFinding("acme", "r1", "ssrf", "https://acme.io", "https://acme.io/a", "p", finding.SeverityCritical))
	s.Save(ctx, mkFinding("acme", "r1", "xss", "https://acme.io", "https://acme.io/b", "p", finding.SeverityLow))
	s.Save(ctx, mkFinding("acme", "r2", "redir", "https://acme.io", "https://acme.io/c", "p", finding.SeverityHigh))

	all, _ := s.List(ctx, Query{Program: "acme"})
	if len(all) != 3 || all[0].Severity != finding.SeverityCritical || all[2].Severity != finding.SeverityLow {
		t.Fatalf("wrong severity order: %d findings", len(all))
	}
	if r, _ := s.List(ctx, Query{Program: "acme", RunID: "r2"}); len(r) != 1 {
		t.Errorf("wrong run_id filter: %d", len(r))
	}
	if r, _ := s.List(ctx, Query{Program: "acme", Types: []string{"ssrf"}}); len(r) != 1 {
		t.Errorf("wrong type filter: %d", len(r))
	}
}

func TestSQLiteListExcludesDuplicates(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	s.Save(ctx, mkFinding("acme", "r", "xss", "https://acme.io", "https://acme.io/s", "q", finding.SeverityHigh))
	s.Save(ctx, mkFinding("acme", "r", "xss", "https://acme.io", "https://acme.io/s", "q", finding.SeverityHigh))

	if def, _ := s.List(ctx, Query{Program: "acme"}); len(def) != 1 {
		t.Fatalf("the default must hide duplicates: %d", len(def))
	}
	if all, _ := s.List(ctx, Query{Program: "acme", IncludeDuplicates: true}); len(all) != 2 {
		t.Fatalf("IncludeDuplicates must show everything: %d", len(all))
	}
}

func TestSQLiteSetStatus(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	res, _ := s.Save(ctx, mkFinding("acme", "r", "ssrf", "https://acme.io", "https://acme.io/x", "p", finding.SeverityHigh))
	if err := s.SetStatus(ctx, res.ID, finding.StatusConfirmed, "gh05t"); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}
	got, _ := s.Get(ctx, res.ID)
	if got.Status != finding.StatusConfirmed || got.VerifiedBy != "gh05t" || got.UpdatedAt == nil {
		t.Errorf("the triage was not saved: %+v", got)
	}
}

func TestSQLiteUpdateContent(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	res, _ := s.Save(ctx, mkFinding("acme", "r", "ssrf", "https://acme.io", "https://acme.io/x", "p", finding.SeverityHigh))
	if err := s.UpdateContent(ctx, res.ID, "desc", "real impact", []string{"step 1", "step 2"}); err != nil {
		t.Fatalf("UpdateContent: %v", err)
	}
	// Read back from the JSON doc -> shows that impact/reproduction survive serialization.
	got, _ := s.Get(ctx, res.ID)
	if got.Impact != "real impact" || got.Description != "desc" || len(got.Reproduction) != 2 {
		t.Errorf("the content was not saved through the JSON doc: %+v", got)
	}
}

func TestSQLitePersistenceAcrossReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "persist.db")

	s1, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("open1: %v", err)
	}
	res, err := s1.Save(ctx, mkFinding("acme", "r", "ssrf", "https://acme.io", "https://acme.io/x", "p", finding.SeverityHigh))
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("close1: %v", err)
	}

	s2, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("open2: %v", err)
	}
	defer s2.Close()

	got, err := s2.Get(ctx, res.ID)
	if err != nil {
		t.Fatalf("Get after reopen: %v", err)
	}
	if got.Type != "ssrf" {
		t.Errorf("the data did not survive a restart: %+v", got)
	}
	if lst, _ := s2.List(ctx, Query{Program: "acme"}); len(lst) != 1 {
		t.Errorf("List after reopen: %d", len(lst))
	}
}

func TestSQLiteProgramCRUDPersists(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "prog.db")

	s1, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s1.SaveProgram(ctx, Program{Name: "demo", InScope: []string{"demo.test", "*.demo.test"}, OutScope: []string{"admin.demo.test"}}); err != nil {
		t.Fatal(err)
	}
	s1.Close()

	s2, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	got, err := s2.GetProgram(ctx, "demo")
	if err != nil {
		t.Fatalf("GetProgram after reopen: %v", err)
	}
	if len(got.InScope) != 2 || got.OutScope[0] != "admin.demo.test" {
		t.Errorf("the scope did not survive a restart: %+v", got)
	}
}

func presetEqual(a, b ScanPreset) bool {
	if a.Stealth != b.Stealth || a.APIRoutes != b.APIRoutes || len(a.Tags) != len(b.Tags) || len(a.Severity) != len(b.Severity) {
		return false
	}
	for i := range a.Tags {
		if a.Tags[i] != b.Tags[i] {
			return false
		}
	}
	for i := range a.Severity {
		if a.Severity[i] != b.Severity[i] {
			return false
		}
	}
	return true
}

func TestSQLiteProgramPresetPersists(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "preset.db")

	s1, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	want := ScanPreset{Tags: []string{"cve", "exposure"}, Severity: []string{"critical", "high"}, Stealth: true, APIRoutes: true}
	if err := s1.SaveProgram(ctx, Program{Name: "demo", InScope: []string{"demo.test"}, Preset: want}); err != nil {
		t.Fatal(err)
	}
	s1.Close()

	s2, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	got, err := s2.GetProgram(ctx, "demo")
	if err != nil {
		t.Fatalf("GetProgram: %v", err)
	}
	if !presetEqual(got.Preset, want) {
		t.Errorf("the preset did not survive a restart: got %+v want %+v", got.Preset, want)
	}
}

// TestSQLiteProgramPresetMigratesOldDB: a DB created before the preset column
// existed (the 4-column programs schema, like the primary's bughound.db) must be
// migrated additively when it is opened. Old rows stay readable (empty preset)
// and a new preset can be saved in the migrated column.
func TestSQLiteProgramPresetMigratesOldDB(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "old.db")

	// Build an OLD-schema programs table (no preset) + one row through the raw driver.
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE programs (name TEXT PRIMARY KEY, in_scope TEXT NOT NULL, out_scope TEXT NOT NULL, updated_at TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO programs (name,in_scope,out_scope,updated_at) VALUES (?,?,?,?)`,
		"legacy", `["a.io"]`, `[]`, "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	// OpenSQLite runs init() → the migration adds the preset column (idempotent).
	s, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("OpenSQLite (migration): %v", err)
	}
	defer s.Close()

	got, err := s.GetProgram(ctx, "legacy")
	if err != nil {
		t.Fatalf("GetProgram of the old row after migration: %v", err)
	}
	if len(got.Preset.Tags) != 0 || len(got.Preset.Severity) != 0 || got.Preset.Stealth {
		t.Errorf("the old row must have an empty preset, got %+v", got.Preset)
	}
	if err := s.SaveProgram(ctx, Program{Name: "legacy", InScope: []string{"a.io"}, Preset: ScanPreset{Tags: []string{"misconfig"}}}); err != nil {
		t.Fatalf("SaveProgram preset after migration: %v", err)
	}
	got2, _ := s.GetProgram(ctx, "legacy")
	if len(got2.Preset.Tags) != 1 || got2.Preset.Tags[0] != "misconfig" {
		t.Errorf("the preset was not saved after migration: %+v", got2.Preset)
	}
}

func TestSQLiteDeleteProgramKeepsFindings(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	// A program with a scope definition + one finding.
	if err := s.SaveProgram(ctx, Program{Name: "demo", InScope: []string{"demo.test"}}); err != nil {
		t.Fatal(err)
	}
	s.Save(ctx, mkFinding("demo", "r", "x", "https://demo.test", "https://demo.test/a", "p", finding.SeverityLow))

	if err := s.DeleteProgram(ctx, "demo"); err != nil {
		t.Fatalf("DeleteProgram: %v", err)
	}
	// The definition is gone...
	if _, err := s.GetProgram(ctx, "demo"); err != ErrNotFound {
		t.Errorf("the program definition must be gone (ErrNotFound), got %v", err)
	}
	if ps, _ := s.ListPrograms(ctx); len(ps) != 0 {
		t.Errorf("ListPrograms must be empty after the delete, got %+v", ps)
	}
	// ...but the finding STAYS (it is work product; the audit/findings are not deleted with it).
	if fs, _ := s.List(ctx, Query{Program: "demo"}); len(fs) != 1 {
		t.Errorf("the finding must still be stored after the program is deleted, got %d", len(fs))
	}
	if ps, _ := s.Programs(ctx); len(ps) != 1 || ps[0] != "demo" {
		t.Errorf("Programs() (from findings) must still contain demo, got %v", ps)
	}
	// Idempotent: deleting again → ErrNotFound.
	if err := s.DeleteProgram(ctx, "demo"); err != ErrNotFound {
		t.Errorf("deleting again must be ErrNotFound, got %v", err)
	}
}

func TestSQLiteDeleteFindingsByProgram(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	s.Save(ctx, mkFinding("A", "r1", "ssrf", "https://a.io", "https://a.io/x", "p", finding.SeverityHigh))
	s.Save(ctx, mkFinding("A", "r1", "xss", "https://a.io", "https://a.io/y", "q", finding.SeverityLow))
	s.Save(ctx, mkFinding("B", "r1", "ssrf", "https://b.io", "https://b.io/x", "p", finding.SeverityHigh))
	s.SaveProgram(ctx, Program{Name: "A", InScope: []string{"a.io"}})

	n, err := s.DeleteFindingsByProgram(ctx, "A")
	if err != nil || n != 2 {
		t.Fatalf("delete = %d,%v; want 2,nil", n, err)
	}
	if fs, _ := s.List(ctx, Query{Program: "A"}); len(fs) != 0 {
		t.Errorf("findings of A must be gone, %d left", len(fs))
	}
	if fs, _ := s.List(ctx, Query{Program: "B"}); len(fs) != 1 {
		t.Errorf("findings of B must stay, got %d", len(fs))
	}
	if _, err := s.GetProgram(ctx, "A"); err != nil {
		t.Errorf("the scope definition of A must stay: %v", err)
	}
	// Dedup is reset (the findings rows = the dedup state in SQLite).
	res, _ := s.Save(ctx, mkFinding("A", "r2", "ssrf", "https://a.io", "https://a.io/x", "p", finding.SeverityHigh))
	if res.Deduplicated {
		t.Error("the old dedup_key must become a primary again after the delete")
	}
	if n, _ := s.DeleteFindingsByProgram(ctx, "empty"); n != 0 {
		t.Errorf("deleting a program without findings = %d; want 0", n)
	}
}

func TestSQLitePrograms(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	s.Save(ctx, mkFinding("beta", "r", "x", "https://b.io", "https://b.io/a", "p", finding.SeverityLow))
	s.Save(ctx, mkFinding("alpha", "r", "x", "https://a.io", "https://a.io/a", "p", finding.SeverityLow))
	s.Save(ctx, mkFinding("alpha", "r", "y", "https://a.io", "https://a.io/b", "p", finding.SeverityLow))
	ps, err := s.Programs(ctx)
	if err != nil {
		t.Fatalf("Programs: %v", err)
	}
	if len(ps) != 2 || ps[0] != "alpha" || ps[1] != "beta" {
		t.Errorf("programs must be unique and sorted: %v", ps)
	}
}
