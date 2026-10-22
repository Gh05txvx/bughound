package orchestrator

import (
	"context"
	"strings"
	"testing"

	"bughound/internal/engine/ffuf"
	"bughound/internal/engine/nuclei"
	"bughound/internal/finding"
	"bughound/internal/ratelimit"
	"bughound/internal/recon"
	"bughound/internal/scope"
	"bughound/internal/store"
)

func newGuard(t *testing.T, in, out []string) *scope.Guard {
	t.Helper()
	g, errs := scope.New(in, out)
	if len(errs) > 0 {
		t.Fatalf("scope.New errs tak terduga: %v", errs)
	}
	return g
}

// testLimiter: burst besar supaya test tak melambat (laju efektif dijepit ke maks).
func testLimiter() *ratelimit.Limiter {
	return ratelimit.New(ratelimit.Config{RequestsPerSecond: 1000, Burst: 1000})
}

// TestRunScanGate membuktikan gate M0 masih berlaku: satu temuan mengalir scan
// -> normalisasi -> store; target luar scope ditolak; secret tak bocor.
func TestRunScanGate(t *testing.T) {
	g := newGuard(t, []string{"demo.test", "*.demo.test"}, nil)
	st := store.NewMem()
	var audit []AuditEvent
	o := New(g, nuclei.Mock{}, st, testLimiter(), func(e AuditEvent) { audit = append(audit, e) })

	res, err := o.RunScan(context.Background(), ScanRequest{
		Program: "demo", RunID: "run1", Targets: []string{"demo.test", "evil.test"},
	})
	if err != nil {
		t.Fatalf("RunScan error: %v", err)
	}
	if res.FindingsSaved != 2 || res.Duplicates != 0 {
		t.Errorf("ingin 2 tersimpan / 0 duplikat; dapat saved=%d dup=%d", res.FindingsSaved, res.Duplicates)
	}
	if len(res.Scanned) != 1 || res.Scanned[0] != "demo.test" {
		t.Errorf("hanya demo.test yang discan; dapat %v", res.Scanned)
	}
	var deniedEvil *AuditEvent
	for i := range res.Denied {
		if res.Denied[i].Target == "evil.test" {
			deniedEvil = &res.Denied[i]
		}
	}
	if deniedEvil == nil || deniedEvil.Layer != LayerInput || deniedEvil.Reason != scope.ReasonNotInScope {
		t.Errorf("evil.test harus ditolak di lapis input (not-in-scope); dapat %+v", res.Denied)
	}
	fs, _ := st.List(context.Background(), store.Query{Program: "demo"})
	if len(fs) != 2 || fs[0].Severity != finding.SeverityCritical {
		t.Fatalf("store tidak sesuai: %d temuan", len(fs))
	}
	for _, f := range fs {
		if f.Evidence != nil && strings.Contains(f.Evidence.Request, "SECRET-abc123") {
			t.Error("secret bocor ke store")
		}
	}
	if len(audit) == 0 {
		t.Error("audit trail kosong")
	}
}

func TestRunScanDedupSecondRun(t *testing.T) {
	g := newGuard(t, []string{"demo.test"}, nil)
	st := store.NewMem()
	o := New(g, nuclei.Mock{}, st, testLimiter(), nil)
	ctx := context.Background()

	if _, err := o.RunScan(ctx, ScanRequest{Program: "demo", RunID: "run1", Targets: []string{"demo.test"}}); err != nil {
		t.Fatal(err)
	}
	res2, err := o.RunScan(ctx, ScanRequest{Program: "demo", RunID: "run2", Targets: []string{"demo.test"}})
	if err != nil {
		t.Fatal(err)
	}
	if res2.FindingsSaved != 0 || res2.Duplicates != 2 {
		t.Errorf("run kedua harus semua duplikat; dapat saved=%d dup=%d", res2.FindingsSaved, res2.Duplicates)
	}
	fs, _ := st.List(ctx, store.Query{Program: "demo"})
	if len(fs) != 2 {
		t.Errorf("harus tetap 2 temuan utama; dapat %d", len(fs))
	}
}

type fakeEngine struct{ out []*finding.Finding }

func (fakeEngine) Name() string { return "fake" }

func (f fakeEngine) Scan(_ context.Context, _ string, program, runID string) ([]*finding.Finding, error) {
	var out []*finding.Finding
	for _, x := range f.out {
		c := *x
		c.Program, c.RunID = program, runID
		out = append(out, &c)
	}
	return out, nil
}

// TestRunScanEgressBlocks membuktikan penegakan lapis kedua: temuan pada lokasi
// di luar scope dihadang walau target awal in-scope.
func TestRunScanEgressBlocks(t *testing.T) {
	g := newGuard(t, []string{"demo.test"}, nil)
	st := store.NewMem()
	var audit []AuditEvent
	eng := fakeEngine{out: []*finding.Finding{{
		Target: "demo.test", Type: "redirect-ssrf", Title: "leak via redirect",
		Severity: finding.SeverityHigh, Confidence: finding.ConfidenceMedium,
		Status: finding.StatusNew, SourceEngine: "fake",
		Location: finding.Location{URL: "https://external.evil/x"},
	}}}
	o := New(g, eng, st, testLimiter(), func(e AuditEvent) { audit = append(audit, e) })

	res, err := o.RunScan(context.Background(), ScanRequest{Program: "demo", RunID: "r", Targets: []string{"demo.test"}})
	if err != nil {
		t.Fatalf("RunScan error: %v", err)
	}
	if res.FindingsSaved != 0 {
		t.Errorf("temuan di luar scope tak boleh tersimpan; saved=%d", res.FindingsSaved)
	}
	if fs, _ := st.List(context.Background(), store.Query{Program: "demo"}); len(fs) != 0 {
		t.Errorf("store harus kosong; dapat %d", len(fs))
	}
	var egressDeny bool
	for _, e := range audit {
		if e.Layer == LayerEgress && !e.Allowed {
			egressDeny = true
		}
	}
	if !egressDeny {
		t.Error("harus ada audit egress-deny untuk temuan di luar scope")
	}
}

// TestRunScanWithRecon membuktikan alur recon → scope guard → DAST: aset recon
// yang in-scope discan; yang out-of-scope/di luar scope ditolak.
func TestRunScanWithRecon(t *testing.T) {
	g := newGuard(t, []string{"demo.test", "*.demo.test"}, []string{"admin.demo.test"})
	st := store.NewMem()
	o := New(g, nuclei.Mock{}, st, testLimiter(), nil)
	o.UseRecon(recon.MockPipeline{})

	res, err := o.RunScan(context.Background(), ScanRequest{
		Program: "demo", RunID: "run1", Seeds: []string{"demo.test"},
	})
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}
	if res.Discovered == 0 {
		t.Error("recon harus menemukan aset")
	}
	if len(res.Scanned) == 0 {
		t.Error("harus ada target in-scope yang discan")
	}
	if res.FindingsSaved != 2 {
		t.Errorf("mock DAST => 2 temuan utama; dapat %d", res.FindingsSaved)
	}

	denied := map[string]scope.Reason{}
	for _, e := range res.Denied {
		denied[e.Target] = e.Reason
	}
	if denied["admin.demo.test"] != scope.ReasonOutOfScope {
		t.Errorf("admin.demo.test harus ditolak out-of-scope; dapat %q", denied["admin.demo.test"])
	}
	if _, ok := denied["exfil.evil.test"]; !ok {
		t.Error("exfil.evil.test (di luar scope) harus ditolak")
	}

	all, _ := st.List(context.Background(), store.Query{Program: "demo", IncludeDuplicates: true})
	for _, f := range all {
		if strings.Contains(f.Target, "evil.test") {
			t.Error("temuan di luar scope tak boleh tersimpan")
		}
	}
}

// TestRunScanMultiEngine membuktikan >1 engine menulis ke skema yang sama.
func TestRunScanMultiEngine(t *testing.T) {
	g := newGuard(t, []string{"demo.test"}, nil)
	st := store.NewMem()
	o := New(g, nuclei.Mock{}, st, testLimiter(), nil)
	o.AddEngine(ffuf.Mock{})

	res, err := o.RunScan(context.Background(), ScanRequest{Program: "demo", RunID: "r", Targets: []string{"demo.test"}})
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}
	// 2 nuclei + 4 ffuf, semua dedup_key berbeda.
	if res.FindingsSaved != 6 {
		t.Errorf("ingin 6 temuan (2 nuclei + 4 ffuf), dapat %d", res.FindingsSaved)
	}
	all, _ := st.List(context.Background(), store.Query{Program: "demo"})
	var hasNuclei, hasFfuf bool
	for _, f := range all {
		switch f.SourceEngine {
		case "nuclei":
			hasNuclei = true
		case "ffuf":
			hasFfuf = true
		}
	}
	if !hasNuclei || !hasFfuf {
		t.Error("nuclei dan ffuf harus sama-sama menyumbang ke skema yang sama")
	}
}
