package orchestrator

import (
	"context"
	"testing"

	"bughound/internal/finding"
	"bughound/internal/store"
)

// oaEngine records the spec it receives through UseOpenAPISpec (engine.OpenAPIAware).
type oaEngine struct{ spec []byte }

func (*oaEngine) Name() string { return "oa" }
func (*oaEngine) Scan(context.Context, string, string, string) ([]*finding.Finding, error) {
	return nil, nil
}
func (e *oaEngine) UseOpenAPISpec(spec []byte) { e.spec = spec }

// The spec on a ScanRequest must be passed on to OpenAPIAware engines.
func TestRunScanThreadsOpenAPISpec(t *testing.T) {
	g := newGuard(t, []string{"demo.test"}, nil)
	eng := &oaEngine{}
	o := New(g, eng, store.NewMem(), testLimiter(), nil)
	spec := []byte(`{"openapi":"3.0.0"}`)
	if _, err := o.RunScan(context.Background(), ScanRequest{Program: "demo", Targets: []string{"demo.test"}, OpenAPISpec: spec}); err != nil {
		t.Fatal(err)
	}
	if string(eng.spec) != string(spec) {
		t.Errorf("the spec was not passed to the OpenAPIAware engine; got %q", eng.spec)
	}
}

// Without a spec, UseOpenAPISpec is not called (the engine receives nothing).
func TestRunScanNoSpecNoCall(t *testing.T) {
	g := newGuard(t, []string{"demo.test"}, nil)
	eng := &oaEngine{}
	o := New(g, eng, store.NewMem(), testLimiter(), nil)
	if _, err := o.RunScan(context.Background(), ScanRequest{Program: "demo", Targets: []string{"demo.test"}}); err != nil {
		t.Fatal(err)
	}
	if eng.spec != nil {
		t.Errorf("without a spec, UseOpenAPISpec must not be called; got %q", eng.spec)
	}
}
