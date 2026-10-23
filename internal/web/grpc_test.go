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
	if b := do(t, srv, "GET", "/grpc", nil).Body.String(); !strings.Contains(b, "Enumerasi gRPC") || !strings.Contains(b, "grpc (mock)") {
		t.Errorf("form gRPC tak ter-render:\n%s", b)
	}

	// Satu target in-scope + satu out-of-scope.
	rec := do(t, srv, "POST", "/grpc/run", url.Values{
		"program": {"gp"},
		"targets": {"api.demo.test:9090\nevil.test:9090"},
	})
	body := rec.Body.String()
	if !strings.Contains(body, "ditolak") || !strings.Contains(body, "evil.test:9090") {
		t.Errorf("target out-of-scope harus ditolak & terdaftar:\n%s", body)
	}
	// Temuan dari target in-scope tersimpan & muncul di Findings.
	if b := do(t, srv, "GET", "/findings?program=gp", nil).Body.String(); !strings.Contains(b, "reflection") {
		t.Errorf("enumerasi gRPC in-scope harus menghasilkan temuan:\n%s", b)
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
	// Mock Fuzz menambah temuan callable-unauth (judul memuat "tanpa autentikasi").
	if b := do(t, srv, "GET", "/findings?program=gp", nil).Body.String(); !strings.Contains(b, "tanpa autentikasi") {
		t.Errorf("fuzz harus menghasilkan temuan callable-unauth:\n%s", b)
	}
}

func TestGRPCRequiresProgramScope(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := do(t, srv, "POST", "/grpc/run", url.Values{
		"program": {"belum-ada"},
		"targets": {"api.demo.test:9090"},
	})
	if !strings.Contains(rec.Body.String(), "belum punya scope") {
		t.Errorf("program tanpa scope tersimpan harus error:\n%s", rec.Body.String())
	}
}
