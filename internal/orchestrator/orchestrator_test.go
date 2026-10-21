package orchestrator

import (
	"context"
	"strings"
	"testing"

	"bughound/internal/engine/nuclei"
	"bughound/internal/finding"
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

// TestRunScanGate membuktikan gate M0: satu temuan mengalir scan -> normalisasi
// -> store; target luar scope ditolak; secret tak bocor; tanpa jaringan.
func TestRunScanGate(t *testing.T) {
	g := newGuard(t, []string{"demo.test", "*.demo.test"}, nil)
	st := store.NewMem()
	var audit []AuditEvent
	o := New(g, nuclei.Mock{}, st, func(e AuditEvent) { audit = append(audit, e) })

	res, err := o.RunScan(context.Background(), ScanRequest{
		Program: "demo",
		RunID:   "run1",
		Targets: []string{"demo.test", "evil.test"},
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
		t.Fatalf("store tidak sesuai: %d temuan, teratas %v", len(fs), sev(fs))
	}
	for _, f := range fs {
		if f.Evidence != nil && strings.Contains(f.Evidence.Request, "SECRET-abc123") {
			t.Error("secret bocor ke store")
		}
	}
	if len(audit) == 0 {
		t.Error("audit trail kosong; keputusan scope harus tercatat")
	}
}

func TestRunScanDedupSecondRun(t *testing.T) {
	g := newGuard(t, []string{"demo.test"}, nil)
	st := store.NewMem()
	o := New(g, nuclei.Mock{}, st, nil)
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
		t.Errorf("harus tetap 2 temuan utama (duplikat disembunyikan); dapat %d", len(fs))
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
// di luar scope (mis. akibat redirect) dihadang walau target awal in-scope.
func TestRunScanEgressBlocks(t *testing.T) {
	g := newGuard(t, []string{"demo.test"}, nil)
	st := store.NewMem()
	var audit []AuditEvent
	eng := fakeEngine{out: []*finding.Finding{{
		Target:       "demo.test",
		Type:         "redirect-ssrf",
		Title:        "leak via redirect",
		Severity:     finding.SeverityHigh,
		Confidence:   finding.ConfidenceMedium,
		Status:       finding.StatusNew,
		SourceEngine: "fake",
		Location:     finding.Location{URL: "https://external.evil/x"}, // di luar scope
	}}}
	o := New(g, eng, st, func(e AuditEvent) { audit = append(audit, e) })

	res, err := o.RunScan(context.Background(), ScanRequest{Program: "demo", RunID: "r", Targets: []string{"demo.test"}})
	if err != nil {
		t.Fatalf("RunScan error: %v", err)
	}
	if res.FindingsSaved != 0 {
		t.Errorf("temuan di luar scope tidak boleh tersimpan; saved=%d", res.FindingsSaved)
	}
	fs, _ := st.List(context.Background(), store.Query{Program: "demo"})
	if len(fs) != 0 {
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

func sev(fs []*finding.Finding) []finding.Severity {
	out := make([]finding.Severity, len(fs))
	for i, f := range fs {
		out[i] = f.Severity
	}
	return out
}
