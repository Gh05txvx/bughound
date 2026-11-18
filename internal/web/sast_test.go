package web

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"bughound/internal/audit"
	"bughound/internal/engine"
	"bughound/internal/engine/ffuf"
	"bughound/internal/engine/nuclei"
	"bughound/internal/recon"
	"bughound/internal/secret"
	"bughound/internal/store"
)

func newSASTServer(t *testing.T, root string) (*Server, *store.Mem, *audit.MemLog) {
	t.Helper()
	st := store.NewMem()
	k, _ := secret.NewRandomKey()
	al := audit.NewMemLog([]byte("sast-test"))
	srv, err := NewServer(Config{
		Store:        st,
		Engines:      []engine.Engine{nuclei.Mock{}, ffuf.Mock{}},
		Recon:        recon.MockPipeline{},
		Vault:        secret.NewMemVault(secret.NewKeyring(k)),
		Audit:        al,
		SASTRoot:     root,
		AuthDisabled: true,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv, st, al
}

func TestSASTDisabledByDefault(t *testing.T) {
	srv, _ := newTestServer(t)
	if b := do(t, srv, "GET", "/sast", nil).Body.String(); !strings.Contains(b, "disabled") {
		t.Errorf("SAST without a root must show disabled:\n%s", b)
	}
}

func TestSASTRunMockAndScope(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	srv, st, al := newSASTServer(t, root)
	ctx := context.Background()

	if b := do(t, srv, "GET", "/sast", nil).Body.String(); !strings.Contains(b, "Run SAST") || !strings.Contains(b, "mock") {
		t.Errorf("the SAST form is not rendered:\n%s", b)
	}

	// Run the mock adapter on the root (subpath "."): 2 findings stored.
	rec := do(t, srv, "POST", "/sast/run", url.Values{"program": {"appsec"}, "subpath": {"."}, "engine": {"mock"}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "new findings") {
		t.Fatalf("running the mock SAST failed: %d\n%s", rec.Code, rec.Body.String())
	}
	if fs, _ := st.List(ctx, store.Query{Program: "appsec"}); len(fs) != 2 {
		t.Fatalf("there must be 2 SAST findings stored; got %d", len(fs))
	}
	// Shows up in Findings through the same schema.
	if b := do(t, srv, "GET", "/findings?program=appsec", nil).Body.String(); !strings.Contains(b, "hardcode") {
		t.Errorf("the SAST finding must show up in Findings:\n%s", b)
	}

	// A path outside the root is denied (fail-closed) + recorded in the audit.
	rec = do(t, srv, "POST", "/sast/run", url.Values{"program": {"appsec"}, "subpath": {"../.."}, "engine": {"mock"}})
	if !strings.Contains(rec.Body.String(), "denied") {
		t.Errorf("a path outside the root must be denied in the UI:\n%s", rec.Body.String())
	}
	if ev, _ := al.List(ctx, audit.Filter{Kind: "sast.scope"}); len(ev) == 0 {
		t.Error("a path denial must be recorded in the audit (sast.scope)")
	}
}
