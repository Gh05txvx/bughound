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
		Title:        typ + " at " + locURL,
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
		t.Fatal("the ID must be filled in automatically")
	}
	if f.DedupKey == "" || f.SchemaVersion != finding.CurrentSchemaVersion || f.CreatedAt.IsZero() {
		t.Error("schema_version/dedup_key/created_at must be filled in by Save")
	}
	if res.Deduplicated {
		t.Error("the first finding must not be treated as a duplicate")
	}
}

func TestDedupMarksDuplicate(t *testing.T) {
	s := NewMem()
	ctx := context.Background()

	// Different run/engine/query, but the same type+host+path+param => a duplicate.
	a := mkFinding("acme", "run1", "xss", "https://acme.io", "https://acme.io/s?q=1", "q", finding.SeverityHigh)
	b := mkFinding("acme", "run2", "xss", "https://acme.io", "https://acme.io/s?q=zzz", "q", finding.SeverityHigh)

	ra, _ := s.Save(ctx, a)
	rb, _ := s.Save(ctx, b)

	if ra.Deduplicated {
		t.Fatal("a should become the main finding")
	}
	if !rb.Deduplicated || rb.PrimaryID != ra.ID {
		t.Fatalf("b should be a duplicate of a: %+v", rb)
	}
	got, _ := s.Get(ctx, rb.ID)
	if got.Status != finding.StatusDuplicate || got.DuplicateOf != ra.ID {
		t.Errorf("b was stored: status=%s duplicate_of=%s", got.Status, got.DuplicateOf)
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
		t.Error("the same dedup_key in different programs must not duplicate each other")
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
		t.Fatalf("the default must hide duplicates: got %d", len(def))
	}
	all, _ := s.List(ctx, Query{Program: "acme", IncludeDuplicates: true})
	if len(all) != 2 {
		t.Fatalf("IncludeDuplicates must show everything: got %d", len(all))
	}
	onlyDup, _ := s.List(ctx, Query{Program: "acme", Statuses: []finding.Status{finding.StatusDuplicate}})
	if len(onlyDup) != 1 {
		t.Fatalf("the status=duplicate filter must return the duplicates: got %d", len(onlyDup))
	}
}

// A site-wide issue (missing CSP) that ZAP reports on many URLs must collapse
// into one main finding: dedup_key ignores the path.
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
		t.Fatalf("CSP on %d URLs must collapse into 1 (the rest are duplicates); duplicates=%d", len(paths), dupes)
	}
	def, _ := s.List(ctx, Query{Program: "acme"})
	if len(def) != 1 {
		t.Fatalf("the default count must be 1 CSP issue, not %d", len(def))
	}
	// Every instance is still stored for audit.
	all, _ := s.List(ctx, Query{Program: "acme", IncludeDuplicates: true})
	if len(all) != len(paths) {
		t.Fatalf("every instance must still be stored (audit): got %d", len(all))
	}
}

func TestListFiltersAndSort(t *testing.T) {
	s := NewMem()
	ctx := context.Background()
	mk := func(runID, typ, path string, sev finding.Severity, at time.Time) {
		f := mkFinding("acme", runID, typ, "https://acme.io", "https://acme.io"+path, "p", sev)
		f.CreatedAt = finding.NewTime(at) // preset so the order is deterministic
		if _, err := s.Save(ctx, f); err != nil {
			t.Fatal(err)
		}
	}
	base := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	mk("run1", "ssrf", "/a", finding.SeverityCritical, base)
	mk("run1", "xss", "/b", finding.SeverityLow, base.Add(time.Hour))
	mk("run2", "xss", "/c", finding.SeverityHigh, base.Add(2*time.Hour))

	// Order: the most severe first.
	all, _ := s.List(ctx, Query{Program: "acme"})
	if len(all) != 3 || all[0].Severity != finding.SeverityCritical || all[2].Severity != finding.SeverityLow {
		t.Fatalf("wrong severity order: %v", sevs(all))
	}
	// Filter run.
	if r, _ := s.List(ctx, Query{Program: "acme", RunID: "run2"}); len(r) != 1 || r[0].Type != "xss" {
		t.Errorf("wrong run_id filter: %d", len(r))
	}
	// Filter severity.
	if r, _ := s.List(ctx, Query{Program: "acme", Severities: []finding.Severity{finding.SeverityHigh, finding.SeverityCritical}}); len(r) != 2 {
		t.Errorf("wrong severity filter: %d", len(r))
	}
	// Filter type.
	if r, _ := s.List(ctx, Query{Program: "acme", Types: []string{"ssrf"}}); len(r) != 1 {
		t.Errorf("wrong type filter: %d", len(r))
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
		t.Errorf("status/verified_by/updated_at were not set: %+v", got)
	}
	if err := s.SetStatus(ctx, "missing", finding.StatusConfirmed, ""); err != ErrNotFound {
		t.Errorf("a missing id must be ErrNotFound, got %v", err)
	}
}

func TestUpdateContent(t *testing.T) {
	s := NewMem()
	ctx := context.Background()
	res, _ := s.Save(ctx, mkFinding("acme", "r", "ssrf", "https://acme.io", "https://acme.io/x", "p", finding.SeverityHigh))

	repro := []string{"Send GET /x", "Observe the internal response"}
	if err := s.UpdateContent(ctx, res.ID, "new description", "impact: SSRF to internal metadata", repro); err != nil {
		t.Fatalf("UpdateContent error: %v", err)
	}
	got, _ := s.Get(ctx, res.ID)
	if got.Description != "new description" || got.Impact != "impact: SSRF to internal metadata" {
		t.Errorf("the description/impact were not set: %+v", got)
	}
	if len(got.Reproduction) != 2 || got.Reproduction[0] != "Send GET /x" {
		t.Errorf("the reproduction was not set: %v", got.Reproduction)
	}
	if got.UpdatedAt == nil {
		t.Error("updated_at must be set")
	}
	// It does not touch status/severity (triage and dedup are separate paths).
	if got.Status != finding.StatusNew || got.Severity != finding.SeverityHigh {
		t.Errorf("UpdateContent must not change status/severity: %+v", got)
	}
	if err := s.UpdateContent(ctx, "missing", "d", "i", nil); err != ErrNotFound {
		t.Errorf("a missing id must be ErrNotFound, got %v", err)
	}
}

func TestGetClonesNoAliasing(t *testing.T) {
	s := NewMem()
	ctx := context.Background()
	f := mkFinding("acme", "r", "ssrf", "https://acme.io", "https://acme.io/x", "p", finding.SeverityHigh)
	res, _ := s.Save(ctx, f)

	got, _ := s.Get(ctx, res.ID)
	got.Title = "CHANGED"
	got.Severity = finding.SeverityInfo

	again, _ := s.Get(ctx, res.ID)
	if again.Title == "CHANGED" || again.Severity == finding.SeverityInfo {
		t.Error("Get must return a copy; a caller's mutation must not leak into the store")
	}
}

func TestSaveRejectsInvalid(t *testing.T) {
	s := NewMem()
	f := mkFinding("acme", "r", "ssrf", "https://acme.io", "https://acme.io/x", "p", "mega") // invalid severity
	if _, err := s.Save(context.Background(), f); err == nil {
		t.Fatal("an invalid severity must be rejected by Save")
	}
}

func TestMemProgramCRUD(t *testing.T) {
	s := NewMem()
	ctx := context.Background()
	if _, err := s.GetProgram(ctx, "demo"); err != ErrNotFound {
		t.Fatalf("a missing program must be ErrNotFound, got %v", err)
	}
	if err := s.SaveProgram(ctx, Program{Name: "demo", InScope: []string{"demo.test"}, OutScope: []string{"admin.demo.test"}}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetProgram(ctx, "demo")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.InScope) != 1 || got.InScope[0] != "demo.test" || len(got.OutScope) != 1 || got.UpdatedAt.IsZero() {
		t.Errorf("the stored program does not match: %+v", got)
	}
	s.SaveProgram(ctx, Program{Name: "demo", InScope: []string{"a", "b"}}) // update
	if g2, _ := s.GetProgram(ctx, "demo"); len(g2.InScope) != 2 {
		t.Error("scope update failed")
	}
	s.SaveProgram(ctx, Program{Name: "alpha"})
	if ps, _ := s.ListPrograms(ctx); len(ps) != 2 || ps[0].Name != "alpha" {
		t.Errorf("ListPrograms must be 2 and sorted: %+v", ps)
	}
	if err := s.SaveProgram(ctx, Program{Name: "  "}); err == nil {
		t.Error("an empty name must be rejected")
	}
	// Delete: delete "demo", keep "alpha"; deleting one that does not exist → ErrNotFound.
	if err := s.DeleteProgram(ctx, "demo"); err != nil {
		t.Fatalf("DeleteProgram: %v", err)
	}
	if _, err := s.GetProgram(ctx, "demo"); err != ErrNotFound {
		t.Errorf("a deleted program must be ErrNotFound, got %v", err)
	}
	if ps, _ := s.ListPrograms(ctx); len(ps) != 1 || ps[0].Name != "alpha" {
		t.Errorf("after the delete [alpha] must remain: %+v", ps)
	}
	if err := s.DeleteProgram(ctx, "demo"); err != ErrNotFound {
		t.Errorf("deleting a missing program must be ErrNotFound, got %v", err)
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
		t.Errorf("programs must be unique and sorted: %v", ps)
	}
}

func TestMemDeleteFindingsByProgram(t *testing.T) {
	s := NewMem()
	ctx := context.Background()
	s.Save(ctx, mkFinding("A", "r1", "ssrf", "https://a.io", "https://a.io/x", "p", finding.SeverityHigh))
	s.Save(ctx, mkFinding("A", "r1", "xss", "https://a.io", "https://a.io/y", "q", finding.SeverityLow))
	s.Save(ctx, mkFinding("B", "r1", "ssrf", "https://b.io", "https://b.io/x", "p", finding.SeverityHigh))
	s.SaveProgram(ctx, Program{Name: "A", InScope: []string{"a.io"}}) // the scope definition must survive

	n, err := s.DeleteFindingsByProgram(ctx, "A")
	if err != nil || n != 2 {
		t.Fatalf("DeleteFindingsByProgram(A) = %d,%v; want 2,nil", n, err)
	}
	if fs, _ := s.List(ctx, Query{Program: "A"}); len(fs) != 0 {
		t.Errorf("findings of A must be gone, %d left", len(fs))
	}
	if fs, _ := s.List(ctx, Query{Program: "B"}); len(fs) != 1 {
		t.Errorf("findings of B (another program) must stay, got %d", len(fs))
	}
	if _, err := s.GetProgram(ctx, "A"); err != nil {
		t.Errorf("the scope definition of A must stay (only findings are deleted): %v", err)
	}
	// The dedup state is reset: the same dedup_key now becomes a primary again.
	res, _ := s.Save(ctx, mkFinding("A", "r2", "ssrf", "https://a.io", "https://a.io/x", "p", finding.SeverityHigh))
	if res.Deduplicated {
		t.Error("after the delete, the old dedup_key must become a primary again")
	}
	// A program without findings → 0, nil (not an error).
	if n, err := s.DeleteFindingsByProgram(ctx, "empty"); n != 0 || err != nil {
		t.Errorf("deleting a program without findings = %d,%v; want 0,nil", n, err)
	}
}
