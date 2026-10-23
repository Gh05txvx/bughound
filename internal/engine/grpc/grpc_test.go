package grpc

import (
	"context"
	"errors"
	"strings"
	"testing"

	"bughound/internal/finding"
)

func TestParseListAndFilter(t *testing.T) {
	out := "grpc.reflection.v1alpha.ServerReflection\ngrpc.health.v1.Health\nacme.UserService\n\nacme.OrderService\n"
	all := parseList(out)
	if len(all) != 4 {
		t.Fatalf("parseList harus 4 baris non-kosong; dapat %d", len(all))
	}
	app := appServices(all)
	if len(app) != 2 || app[0] != "acme.UserService" || app[1] != "acme.OrderService" {
		t.Errorf("appServices harus menyaring reflection/health; dapat %v", app)
	}
}

func TestMockScanFindings(t *testing.T) {
	fs, err := Mock{}.Scan(context.Background(), "api.demo.test:9090", "demo", "run1")
	if err != nil {
		t.Fatal(err)
	}
	// 1 reflection + 2 service + 3 method = 6.
	if len(fs) != 6 {
		t.Fatalf("harus 6 temuan; dapat %d", len(fs))
	}
	var refl, svc, meth int
	for _, f := range fs {
		if f.Target != "api.demo.test:9090" || f.SourceEngine != "grpc" {
			t.Errorf("target/engine salah: %+v", f)
		}
		switch f.Type {
		case "grpc-reflection-enabled":
			refl++
			if f.Severity != finding.SeverityMedium || len(f.CWE) != 1 || f.CWE[0] != "CWE-200" {
				t.Errorf("reflection finding salah: %+v", f)
			}
		case "grpc-service-exposed":
			svc++
		case "grpc-method-exposed":
			meth++
		}
	}
	if refl != 1 || svc != 2 || meth != 3 {
		t.Errorf("komposisi temuan salah: refl=%d svc=%d meth=%d", refl, svc, meth)
	}
}

func TestRunnerArgs(t *testing.T) {
	r := &Runner{Plaintext: true}
	got := strings.Join(r.listArgs("api.demo.test:9090"), " ")
	for _, w := range []string{"-plaintext", "api.demo.test:9090", "list"} {
		if !strings.Contains(got, w) {
			t.Errorf("args harus memuat %q; dapat %q", w, got)
		}
	}
	// per-layanan: nama service ikut.
	if j := strings.Join(r.listArgs("t:1", "acme.UserService"), " "); !strings.Contains(j, "acme.UserService") {
		t.Errorf("args per-layanan harus memuat nama service; dapat %q", j)
	}
	// tanpa plaintext → tak ada flag.
	if strings.Contains(strings.Join((&Runner{}).listArgs("t:1"), " "), "-plaintext") {
		t.Error("tanpa Plaintext tak boleh ada -plaintext")
	}
}

func TestInvokeArgs(t *testing.T) {
	got := strings.Join((&Runner{Plaintext: true}).invokeArgs("t:1", "a.B.GetX"), " ")
	for _, w := range []string{"-plaintext", "-d {}", "t:1", "a.B.GetX"} {
		if !strings.Contains(got, w) {
			t.Errorf("invokeArgs harus memuat %q; dapat %q", w, got)
		}
	}
}

func TestReadOnlyMethod(t *testing.T) {
	cases := map[string]bool{
		"acme.UserService.GetUser":     true,
		"acme.UserService.ListUsers":   true,
		"x.Y.QueryStuff":               true,
		"acme.OrderService.CreateOrder": false,
		"x.Y.DeleteThing":              false,
		"x.Y.UpdateFoo":                false,
	}
	for m, want := range cases {
		if got := readOnlyMethod(m); got != want {
			t.Errorf("readOnlyMethod(%q) = %v; ingin %v", m, got, want)
		}
	}
}

func TestClassifyInvoke(t *testing.T) {
	e := errors.New("exit status 1")
	if classifyInvoke("{\"ok\":true}", nil) != "OK" {
		t.Error("sukses harus OK")
	}
	if got := classifyInvoke("ERROR:\n  Code: Unauthenticated\n  Message: x", e); got != "Unauthenticated" {
		t.Errorf("Unauthenticated; dapat %q", got)
	}
	if got := classifyInvoke("ERROR:\n  Code: InvalidArgument\n  Message: y", e); got != "InvalidArgument" {
		t.Errorf("InvalidArgument; dapat %q", got)
	}
	if got := classifyInvoke("weird output", e); got != "Unknown" {
		t.Errorf("Unknown; dapat %q", got)
	}
}

func TestMockFuzzAddsUnauthFinding(t *testing.T) {
	fs, err := Mock{}.Fuzz(context.Background(), "api.demo.test:9090", "demo", "run1")
	if err != nil {
		t.Fatal(err)
	}
	// 6 enumerasi + 1 fuzz (callable-unauth) = 7.
	if len(fs) != 7 {
		t.Fatalf("Fuzz harus 7 temuan (6 enum + 1 fuzz); dapat %d", len(fs))
	}
	var unauth *finding.Finding
	for _, f := range fs {
		if f.Type == "grpc-method-callable-unauth" {
			unauth = f
		}
	}
	if unauth == nil {
		t.Fatal("harus ada temuan grpc-method-callable-unauth")
	}
	if unauth.Severity != finding.SeverityMedium || len(unauth.CWE) == 0 || unauth.CWE[0] != "CWE-306" {
		t.Errorf("temuan unauth salah: %+v", unauth)
	}
}

// fuzzFinding untuk status terproteksi tidak melaporkan temuan.
func TestFuzzFindingProtectedNil(t *testing.T) {
	if fuzzFinding("t:1", "a.B.GetX", "Unauthenticated", "p", "r") != nil {
		t.Error("Unauthenticated tak boleh menghasilkan temuan")
	}
	if fuzzFinding("t:1", "a.B.GetX", "PermissionDenied", "p", "r") != nil {
		t.Error("PermissionDenied tak boleh menghasilkan temuan")
	}
	if fuzzFinding("t:1", "a.B.GetX", "OK", "p", "r") == nil {
		t.Error("OK harus menghasilkan temuan callable-unauth")
	}
}
