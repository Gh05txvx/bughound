package orchestrator

import (
	"context"
	"testing"

	"bughound/internal/finding"
	"bughound/internal/store"
)

// oaEngine merekam spec yang diterima lewat UseOpenAPISpec (engine.OpenAPIAware).
type oaEngine struct{ spec []byte }

func (*oaEngine) Name() string { return "oa" }
func (*oaEngine) Scan(context.Context, string, string, string) ([]*finding.Finding, error) {
	return nil, nil
}
func (e *oaEngine) UseOpenAPISpec(spec []byte) { e.spec = spec }

// Spec pada ScanRequest harus diteruskan ke engine OpenAPIAware.
func TestRunScanThreadsOpenAPISpec(t *testing.T) {
	g := newGuard(t, []string{"demo.test"}, nil)
	eng := &oaEngine{}
	o := New(g, eng, store.NewMem(), testLimiter(), nil)
	spec := []byte(`{"openapi":"3.0.0"}`)
	if _, err := o.RunScan(context.Background(), ScanRequest{Program: "demo", Targets: []string{"demo.test"}, OpenAPISpec: spec}); err != nil {
		t.Fatal(err)
	}
	if string(eng.spec) != string(spec) {
		t.Errorf("spec tak diteruskan ke engine OpenAPIAware; dapat %q", eng.spec)
	}
}

// Tanpa spec, UseOpenAPISpec tak dipanggil (engine tak menerima apa pun).
func TestRunScanNoSpecNoCall(t *testing.T) {
	g := newGuard(t, []string{"demo.test"}, nil)
	eng := &oaEngine{}
	o := New(g, eng, store.NewMem(), testLimiter(), nil)
	if _, err := o.RunScan(context.Background(), ScanRequest{Program: "demo", Targets: []string{"demo.test"}}); err != nil {
		t.Fatal(err)
	}
	if eng.spec != nil {
		t.Errorf("tanpa spec, UseOpenAPISpec tak boleh dipanggil; dapat %q", eng.spec)
	}
}
