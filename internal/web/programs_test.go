package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"bughound/internal/store"
)

func TestProgramsPersistAndScopeEditor(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()

	// Simpan program lewat scope editor.
	rec := do(t, srv, "POST", "/programs", url.Values{
		"name": {"acme"}, "in_scope": {"acme.io\n*.acme.io"}, "out_scope": {"admin.acme.io"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("simpan program = %d, ingin 303", rec.Code)
	}

	// Persisten di store.
	p, err := st.GetProgram(ctx, "acme")
	if err != nil || len(p.InScope) != 2 || len(p.OutScope) != 1 {
		t.Fatalf("program tak tersimpan dengan benar: %+v (%v)", p, err)
	}

	// Daftar program menampilkannya.
	if b := do(t, srv, "GET", "/programs", nil).Body.String(); !strings.Contains(b, "acme") {
		t.Error("daftar program tak menampilkan 'acme'")
	}

	// Form scan prefill scope dari program tersimpan.
	if b := do(t, srv, "GET", "/scan?program=acme", nil).Body.String(); !strings.Contains(b, "*.acme.io") {
		t.Error("form scan tak prefill scope dari program tersimpan")
	}

	// Pratinjau: izin untuk in-scope, tolak untuk out-of-scope.
	rec = do(t, srv, "POST", "/programs/preview", url.Values{
		"in_scope": {"acme.io\n*.acme.io"}, "out_scope": {"admin.acme.io"},
		"targets": {"app.acme.io\nadmin.acme.io\nevil.com"},
	})
	pb := rec.Body.String()
	if !strings.Contains(pb, "izin") || !strings.Contains(pb, "tolak") {
		t.Errorf("pratinjau harus menampilkan izin & tolak:\n%s", pb)
	}

	// Fail-closed: entri scope tak valid ditolak saat simpan (bukan 303).
	rec = do(t, srv, "POST", "/programs", url.Values{
		"name": {"bad"}, "in_scope": {"ok.io"}, "out_scope": {"a.*.io"},
	})
	if rec.Code == http.StatusSeeOther {
		t.Error("entri scope tak valid harus ditolak (fail-closed), bukan disimpan")
	}
	if _, err := st.GetProgram(ctx, "bad"); err != store.ErrNotFound {
		t.Error("program dengan scope tak valid tak boleh tersimpan")
	}
}
