package store

import (
	"context"
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
		t.Fatalf("hasil Save tak terduga: %+v", res)
	}
	got, err := s.Get(ctx, res.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Type != "ssrf" || got.Severity != finding.SeverityCritical || got.DedupKey == "" {
		t.Errorf("temuan tersimpan tak sesuai: %+v", got)
	}
	if _, err := s.Get(ctx, "tidak-ada"); err != ErrNotFound {
		t.Errorf("id tak ada harus ErrNotFound, dapat %v", err)
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
		t.Fatal("a harus jadi primary")
	}
	if !rb.Deduplicated || rb.PrimaryID != ra.ID {
		t.Fatalf("b harus duplikat dari a: %+v", rb)
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
		t.Error("dedup_key sama di program berbeda tak boleh saling duplikat")
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
		t.Fatalf("urutan severity salah: %d temuan", len(all))
	}
	if r, _ := s.List(ctx, Query{Program: "acme", RunID: "r2"}); len(r) != 1 {
		t.Errorf("filter run_id salah: %d", len(r))
	}
	if r, _ := s.List(ctx, Query{Program: "acme", Types: []string{"ssrf"}}); len(r) != 1 {
		t.Errorf("filter type salah: %d", len(r))
	}
}

func TestSQLiteListExcludesDuplicates(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()
	s.Save(ctx, mkFinding("acme", "r", "xss", "https://acme.io", "https://acme.io/s", "q", finding.SeverityHigh))
	s.Save(ctx, mkFinding("acme", "r", "xss", "https://acme.io", "https://acme.io/s", "q", finding.SeverityHigh))

	if def, _ := s.List(ctx, Query{Program: "acme"}); len(def) != 1 {
		t.Fatalf("default harus sembunyikan duplikat: %d", len(def))
	}
	if all, _ := s.List(ctx, Query{Program: "acme", IncludeDuplicates: true}); len(all) != 2 {
		t.Fatalf("IncludeDuplicates harus tampilkan semua: %d", len(all))
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
		t.Errorf("triase tak tersimpan: %+v", got)
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
		t.Fatalf("Get setelah reopen: %v", err)
	}
	if got.Type != "ssrf" {
		t.Errorf("data tak bertahan lintas-restart: %+v", got)
	}
	if lst, _ := s2.List(ctx, Query{Program: "acme"}); len(lst) != 1 {
		t.Errorf("List setelah reopen: %d", len(lst))
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
		t.Errorf("programs harus unik & terurut: %v", ps)
	}
}
