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
	if b := do(t, srv, "GET", "/sast", nil).Body.String(); !strings.Contains(b, "dinonaktifkan") {
		t.Errorf("SAST tanpa root harus tampil nonaktif:\n%s", b)
	}
}

func TestSASTRunMockAndScope(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	srv, st, al := newSASTServer(t, root)
	ctx := context.Background()

	if b := do(t, srv, "GET", "/sast", nil).Body.String(); !strings.Contains(b, "Jalankan SAST") || !strings.Contains(b, "mock") {
		t.Errorf("form SAST tak ter-render:\n%s", b)
	}

	// Jalankan adapter mock pada root (subpath "."): 2 temuan tersimpan.
	rec := do(t, srv, "POST", "/sast/run", url.Values{"program": {"appsec"}, "subpath": {"."}, "engine": {"mock"}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "temuan baru") {
		t.Fatalf("run SAST mock gagal: %d\n%s", rec.Code, rec.Body.String())
	}
	if fs, _ := st.List(ctx, store.Query{Program: "appsec"}); len(fs) != 2 {
		t.Fatalf("harus 2 temuan SAST tersimpan; dapat %d", len(fs))
	}
	// Muncul di Findings lewat skema yang sama.
	if b := do(t, srv, "GET", "/findings?program=appsec", nil).Body.String(); !strings.Contains(b, "hardcode") {
		t.Errorf("temuan SAST harus muncul di Findings:\n%s", b)
	}

	// Path di luar root ditolak (fail-closed) + tercatat audit.
	rec = do(t, srv, "POST", "/sast/run", url.Values{"program": {"appsec"}, "subpath": {"../.."}, "engine": {"mock"}})
	if !strings.Contains(rec.Body.String(), "ditolak") {
		t.Errorf("path di luar root harus ditolak di UI:\n%s", rec.Body.String())
	}
	if ev, _ := al.List(ctx, audit.Filter{Kind: "sast.scope"}); len(ev) == 0 {
		t.Error("penolakan path harus tercatat di audit (sast.scope)")
	}
}
