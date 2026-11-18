package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"bughound/internal/store"
)

func TestGRPCEnumScopeChecked(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()
	if err := st.SaveProgram(ctx, store.Program{
		Name: "gp", InScope: []string{"demo.test", "*.demo.test"}, OutScope: []string{"evil.test"},
	}); err != nil {
		t.Fatal(err)
	}

	// Form render + engine mock.
	if b := do(t, srv, "GET", "/grpc", nil).Body.String(); !strings.Contains(b, "Enumerate gRPC") || !strings.Contains(b, "grpc (mock)") {
		t.Errorf("the gRPC form is not rendered:\n%s", b)
	}

	// One in-scope + one out-of-scope target.
	rec := do(t, srv, "POST", "/grpc/run", url.Values{
		"program": {"gp"},
		"targets": {"api.demo.test:9090\nevil.test:9090"},
	})
	body := rec.Body.String()
	if !strings.Contains(body, "denied") || !strings.Contains(body, "evil.test:9090") {
		t.Errorf("the out-of-scope target must be denied & listed:\n%s", body)
	}
	// A finding from the in-scope target is stored & shows up in Findings.
	if b := do(t, srv, "GET", "/findings?program=gp", nil).Body.String(); !strings.Contains(b, "reflection") {
		t.Errorf("an in-scope gRPC enumeration must produce a finding:\n%s", b)
	}
}

func TestGRPCFuzzInvokesReadOnly(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()
	if err := st.SaveProgram(ctx, store.Program{Name: "gp", InScope: []string{"demo.test", "*.demo.test"}}); err != nil {
		t.Fatal(err)
	}
	rec := do(t, srv, "POST", "/grpc/run", url.Values{
		"program": {"gp"}, "targets": {"api.demo.test:9090"}, "fuzz": {"on"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("grpc fuzz = %d", rec.Code)
	}
	// Mock Fuzz adds a callable-unauth finding (the title holds "without authentication").
	if b := do(t, srv, "GET", "/findings?program=gp", nil).Body.String(); !strings.Contains(b, "without authentication") {
		t.Errorf("fuzz must produce a callable-unauth finding:\n%s", b)
	}
}

func TestGRPCRequiresProgramScope(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := do(t, srv, "POST", "/grpc/run", url.Values{
		"program": {"missing"},
		"targets": {"api.demo.test:9090"},
	})
	if !strings.Contains(rec.Body.String(), "no saved scope") {
		t.Errorf("a program with no saved scope must error:\n%s", rec.Body.String())
	}
}
