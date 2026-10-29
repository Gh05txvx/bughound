package store

import (
	"context"
	"testing"
	"time"

	"bughound/internal/finding"
)

func mkFinding(program, runID, typ, target, locURL, param string, sev finding.Severity) *finding.Finding {
	return &finding.Finding{
		Program:      program,
		RunID:        runID,
		Target:       target,
		Type:         typ,
		Title:        typ + " pada " + locURL,
		Severity:     sev,
		Confidence:   finding.ConfidenceMedium,
		Status:       finding.StatusNew,
		SourceEngine: "nuclei",
		Location:     finding.Location{URL: locURL, Parameter: param},
	}
}

func TestSaveAssignsDerivedFields(t *testing.T) {
	s := NewMem()
	f := mkFinding("acme", "run1", "ssrf", "https://acme.io", "https://acme.io/fetch", "url", finding.SeverityCritical)
	res, err := s.Save(context.Background(), f)
	if err != nil {
		t.Fatalf("Save error: %v", err)
	}
	if res.ID == "" || f.ID == "" {
		t.Fatal("ID harus terisi otomatis")
	}
	if f.DedupKey == "" || f.SchemaVersion != finding.CurrentSchemaVersion || f.CreatedAt.IsZero() {
		t.Error("schema_version/dedup_key/created_at harus terisi oleh Save")
	}
	if res.Deduplicated {
		t.Error("temuan pertama tidak boleh dianggap duplikat")
	}
}

func TestDedupMarksDuplicate(t *testing.T) {
	s := NewMem()
	ctx := context.Background()

	// run/engine/query berbeda, tapi type+host+path+param sama => duplikat.
	a := mkFinding("acme", "run1", "xss", "https://acme.io", "https://acme.io/s?q=1", "q", finding.SeverityHigh)
	b := mkFinding("acme", "run2", "xss", "https://acme.io", "https://acme.io/s?q=zzz", "q", finding.SeverityHigh)

	ra, _ := s.Save(ctx, a)
	rb, _ := s.Save(ctx, b)

	if ra.Deduplicated {
		t.Fatal("a seharusnya jadi temuan utama")
	}
	if !rb.Deduplicated || rb.PrimaryID != ra.ID {
		t.Fatalf("b seharusnya duplikat dari a: %+v", rb)
	}
	got, _ := s.Get(ctx, rb.ID)
	if got.Status != finding.StatusDuplicate || got.DuplicateOf != ra.ID {
		t.Errorf("b tersimpan: status=%s duplicate_of=%s", got.Status, got.DuplicateOf)
	}
}

func TestDedupIsolatedPerProgram(t *testing.T) {
	s := NewMem()
	ctx := context.Background()
	a := mkFinding("prog-a", "r", "ssrf", "https://acme.io", "https://acme.io/x", "p", finding.SeverityLow)
	b := mkFinding("prog-b", "r", "ssrf", "https://acme.io", "https://acme.io/x", "p", finding.SeverityLow)
	ra, _ := s.Save(ctx, a)
	rb, _ := s.Save(ctx, b)
	if ra.Deduplicated || rb.Deduplicated {
		t.Error("dedup_key sama di program berbeda tidak boleh saling menduplikasi")
	}
}

func TestListExcludesDuplicatesByDefault(t *testing.T) {
	s := NewMem()
	ctx := context.Background()
	a := mkFinding("acme", "r", "xss", "https://acme.io", "https://acme.io/s", "q", finding.SeverityHigh)
	b := mkFinding("acme", "r", "xss", "https://acme.io", "https://acme.io/s", "q", finding.SeverityHigh)
	s.Save(ctx, a)
	s.Save(ctx, b)

	def, _ := s.List(ctx, Query{Program: "acme"})
	if len(def) != 1 {
		t.Fatalf("default harus sembunyikan duplikat: dapat %d", len(def))
	}
	all, _ := s.List(ctx, Query{Program: "acme", IncludeDuplicates: true})
	if len(all) != 2 {
		t.Fatalf("IncludeDuplicates harus tampilkan semua: dapat %d", len(all))
	}
	onlyDup, _ := s.List(ctx, Query{Program: "acme", Statuses: []finding.Status{finding.StatusDuplicate}})
	if len(onlyDup) != 1 {
		t.Fatalf("filter status=duplicate harus kembalikan duplikat: dapat %d", len(onlyDup))
	}
}

// Isu site-wide (CSP absen) yang dilaporkan ZAP di banyak URL harus terkolaps
// jadi satu temuan utama — path diabaikan oleh dedup_key.
func TestDedupSiteWideCollapsesAcrossPaths(t *testing.T) {
	s := NewMem()
	ctx := context.Background()
	const typ = "content-security-policy-csp-header-not-set"
	paths := []string{"https://acme.io/", "https://acme.io/ftp", "https://acme.io/ftp/quarantine", "https://acme.io/sitemap.xml"}
	dupes := 0
	for _, u := range paths {
		r, err := s.Save(ctx, mkFinding("acme", "r", typ, "https://acme.io", u, "", finding.SeverityMedium))
		if err != nil {
			t.Fatal(err)
		}
		if r.Deduplicated {
			dupes++
		}
	}
	if dupes != len(paths)-1 {
		t.Fatalf("CSP di %d URL harus kolaps jadi 1 (sisanya duplikat); duplikat=%d", len(paths), dupes)
	}
	def, _ := s.List(ctx, Query{Program: "acme"})
	if len(def) != 1 {
		t.Fatalf("hitungan default harus 1 isu CSP, bukan %d", len(def))
	}
	// Semua instance tetap tersimpan untuk audit.
	all, _ := s.List(ctx, Query{Program: "acme", IncludeDuplicates: true})
	if len(all) != len(paths) {
		t.Fatalf("semua instance harus tetap tersimpan (audit): dapat %d", len(all))
	}
}

func TestListFiltersAndSort(t *testing.T) {
	s := NewMem()
	ctx := context.Background()
	mk := func(runID, typ, path string, sev finding.Severity, at time.Time) {
		f := mkFinding("acme", runID, typ, "https://acme.io", "https://acme.io"+path, "p", sev)
		f.CreatedAt = finding.NewTime(at) // pra-set agar urutan deterministik
		if _, err := s.Save(ctx, f); err != nil {
			t.Fatal(err)
		}
	}
	base := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	mk("run1", "ssrf", "/a", finding.SeverityCritical, base)
	mk("run1", "xss", "/b", finding.SeverityLow, base.Add(time.Hour))
	mk("run2", "xss", "/c", finding.SeverityHigh, base.Add(2*time.Hour))

	// Urutan: severity terberat dulu.
	all, _ := s.List(ctx, Query{Program: "acme"})
	if len(all) != 3 || all[0].Severity != finding.SeverityCritical || all[2].Severity != finding.SeverityLow {
		t.Fatalf("urutan severity salah: %v", sevs(all))
	}
	// Filter run.
	if r, _ := s.List(ctx, Query{Program: "acme", RunID: "run2"}); len(r) != 1 || r[0].Type != "xss" {
		t.Errorf("filter run_id salah: %d", len(r))
	}
	// Filter severity.
	if r, _ := s.List(ctx, Query{Program: "acme", Severities: []finding.Severity{finding.SeverityHigh, finding.SeverityCritical}}); len(r) != 2 {
		t.Errorf("filter severity salah: %d", len(r))
	}
	// Filter type.
	if r, _ := s.List(ctx, Query{Program: "acme", Types: []string{"ssrf"}}); len(r) != 1 {
		t.Errorf("filter type salah: %d", len(r))
	}
}

func sevs(fs []*finding.Finding) []finding.Severity {
	out := make([]finding.Severity, len(fs))
	for i, f := range fs {
		out[i] = f.Severity
	}
	return out
}

func TestSetStatus(t *testing.T) {
	s := NewMem()
	ctx := context.Background()
	f := mkFinding("acme", "r", "ssrf", "https://acme.io", "https://acme.io/x", "p", finding.SeverityHigh)
	res, _ := s.Save(ctx, f)

	if err := s.SetStatus(ctx, res.ID, finding.StatusConfirmed, "gh05t"); err != nil {
		t.Fatalf("SetStatus error: %v", err)
	}
	got, _ := s.Get(ctx, res.ID)
	if got.Status != finding.StatusConfirmed || got.VerifiedBy != "gh05t" || got.UpdatedAt == nil {
		t.Errorf("status/verified_by/updated_at tidak terset: %+v", got)
	}
	if err := s.SetStatus(ctx, "tidak-ada", finding.StatusConfirmed, ""); err != ErrNotFound {
		t.Errorf("id tak ada harus ErrNotFound, dapat %v", err)
	}
}

func TestGetClonesNoAliasing(t *testing.T) {
	s := NewMem()
	ctx := context.Background()
	f := mkFinding("acme", "r", "ssrf", "https://acme.io", "https://acme.io/x", "p", finding.SeverityHigh)
	res, _ := s.Save(ctx, f)

	got, _ := s.Get(ctx, res.ID)
	got.Title = "DIUBAH"
	got.Severity = finding.SeverityInfo

	again, _ := s.Get(ctx, res.ID)
	if again.Title == "DIUBAH" || again.Severity == finding.SeverityInfo {
		t.Error("Get harus mengembalikan salinan; mutasi pemanggil tidak boleh bocor ke store")
	}
}

func TestSaveRejectsInvalid(t *testing.T) {
	s := NewMem()
	f := mkFinding("acme", "r", "ssrf", "https://acme.io", "https://acme.io/x", "p", "mega") // severity ilegal
	if _, err := s.Save(context.Background(), f); err == nil {
		t.Fatal("severity tidak sah harus ditolak Save")
	}
}

func TestMemProgramCRUD(t *testing.T) {
	s := NewMem()
	ctx := context.Background()
	if _, err := s.GetProgram(ctx, "demo"); err != ErrNotFound {
		t.Fatalf("program tak ada harus ErrNotFound, dapat %v", err)
	}
	if err := s.SaveProgram(ctx, Program{Name: "demo", InScope: []string{"demo.test"}, OutScope: []string{"admin.demo.test"}}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetProgram(ctx, "demo")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.InScope) != 1 || got.InScope[0] != "demo.test" || len(got.OutScope) != 1 || got.UpdatedAt.IsZero() {
		t.Errorf("program tersimpan tak sesuai: %+v", got)
	}
	s.SaveProgram(ctx, Program{Name: "demo", InScope: []string{"a", "b"}}) // update
	if g2, _ := s.GetProgram(ctx, "demo"); len(g2.InScope) != 2 {
		t.Error("update scope gagal")
	}
	s.SaveProgram(ctx, Program{Name: "alpha"})
	if ps, _ := s.ListPrograms(ctx); len(ps) != 2 || ps[0].Name != "alpha" {
		t.Errorf("ListPrograms harus 2 & terurut: %+v", ps)
	}
	if err := s.SaveProgram(ctx, Program{Name: "  "}); err == nil {
		t.Error("nama kosong harus ditolak")
	}
	// Delete: hapus "demo", sisakan "alpha"; hapus yang tak ada → ErrNotFound.
	if err := s.DeleteProgram(ctx, "demo"); err != nil {
		t.Fatalf("DeleteProgram: %v", err)
	}
	if _, err := s.GetProgram(ctx, "demo"); err != ErrNotFound {
		t.Errorf("program terhapus harus ErrNotFound, dapat %v", err)
	}
	if ps, _ := s.ListPrograms(ctx); len(ps) != 1 || ps[0].Name != "alpha" {
		t.Errorf("setelah hapus harus sisa [alpha]: %+v", ps)
	}
	if err := s.DeleteProgram(ctx, "demo"); err != ErrNotFound {
		t.Errorf("hapus program tak ada harus ErrNotFound, dapat %v", err)
	}
}

func TestMemPrograms(t *testing.T) {
	s := NewMem()
	ctx := context.Background()
	s.Save(ctx, mkFinding("beta", "r", "x", "https://b.io", "https://b.io/a", "p", finding.SeverityLow))
	s.Save(ctx, mkFinding("alpha", "r", "x", "https://a.io", "https://a.io/a", "p", finding.SeverityLow))
	s.Save(ctx, mkFinding("alpha", "r", "y", "https://a.io", "https://a.io/b", "p", finding.SeverityLow))
	ps, _ := s.Programs(ctx)
	if len(ps) != 2 || ps[0] != "alpha" || ps[1] != "beta" {
		t.Errorf("programs harus unik & terurut: %v", ps)
	}
}

func TestMemDeleteFindingsByProgram(t *testing.T) {
	s := NewMem()
	ctx := context.Background()
	s.Save(ctx, mkFinding("A", "r1", "ssrf", "https://a.io", "https://a.io/x", "p", finding.SeverityHigh))
	s.Save(ctx, mkFinding("A", "r1", "xss", "https://a.io", "https://a.io/y", "q", finding.SeverityLow))
	s.Save(ctx, mkFinding("B", "r1", "ssrf", "https://b.io", "https://b.io/x", "p", finding.SeverityHigh))
	s.SaveProgram(ctx, Program{Name: "A", InScope: []string{"a.io"}}) // definisi scope harus bertahan

	n, err := s.DeleteFindingsByProgram(ctx, "A")
	if err != nil || n != 2 {
		t.Fatalf("DeleteFindingsByProgram(A) = %d,%v; ingin 2,nil", n, err)
	}
	if fs, _ := s.List(ctx, Query{Program: "A"}); len(fs) != 0 {
		t.Errorf("temuan A harus habis, sisa %d", len(fs))
	}
	if fs, _ := s.List(ctx, Query{Program: "B"}); len(fs) != 1 {
		t.Errorf("temuan B (program lain) harus tetap, dapat %d", len(fs))
	}
	if _, err := s.GetProgram(ctx, "A"); err != nil {
		t.Errorf("definisi scope A harus tetap (hanya temuan dihapus): %v", err)
	}
	// State dedup ter-reset: dedup_key yang sama kini jadi primary lagi.
	res, _ := s.Save(ctx, mkFinding("A", "r2", "ssrf", "https://a.io", "https://a.io/x", "p", finding.SeverityHigh))
	if res.Deduplicated {
		t.Error("setelah hapus, dedup_key lama harus jadi primary lagi")
	}
	// Program tanpa temuan → 0, nil (bukan error).
	if n, err := s.DeleteFindingsByProgram(ctx, "kosong"); n != 0 || err != nil {
		t.Errorf("hapus program tanpa temuan = %d,%v; ingin 0,nil", n, err)
	}
}
