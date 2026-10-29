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

func TestProgramDelete(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()

	// Buat program, pastikan muncul di daftar.
	do(t, srv, "POST", "/programs", url.Values{"name": {"delme"}, "in_scope": {"delme.test"}})
	if _, err := st.GetProgram(ctx, "delme"); err != nil {
		t.Fatalf("prasyarat: program tak tersimpan: %v", err)
	}
	if b := do(t, srv, "GET", "/programs", nil).Body.String(); !strings.Contains(b, "delme") {
		t.Fatal("prasyarat: daftar tak menampilkan 'delme'")
	}

	// Hapus → 303 ke /programs?ok=deleted.
	rec := do(t, srv, "POST", "/programs/delete", url.Values{"name": {"delme"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("hapus program = %d, ingin 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "ok=deleted") {
		t.Errorf("redirect harus membawa ok=deleted, dapat %q", loc)
	}

	// Definisi hilang dari store & daftar; flash muncul.
	if _, err := st.GetProgram(ctx, "delme"); err != store.ErrNotFound {
		t.Errorf("program harus terhapus dari store, dapat %v", err)
	}
	body := do(t, srv, "GET", "/programs?ok=deleted", nil).Body.String()
	if strings.Contains(body, ">delme<") {
		t.Error("daftar masih menampilkan 'delme' setelah hapus")
	}
	if !strings.Contains(body, "Program dihapus") {
		t.Error("flash konfirmasi hapus tak muncul")
	}

	// Idempoten: hapus ulang tetap 303 (sukses senyap), tak 500.
	if rec := do(t, srv, "POST", "/programs/delete", url.Values{"name": {"delme"}}); rec.Code != http.StatusSeeOther {
		t.Errorf("hapus ulang = %d, ingin 303 (idempoten)", rec.Code)
	}
}

func TestProgramDeleteViewerForbidden(t *testing.T) {
	srv, st := newRBACServer(t)
	// Seed satu program langsung di store (bukan lewat viewer).
	if err := st.SaveProgram(context.Background(), store.Program{Name: "keep", InScope: []string{"keep.test"}}); err != nil {
		t.Fatal(err)
	}
	csrf, sess := loginAs(t, srv, "view", "viewpw")
	if rec := authedReq(srv, "POST", "/programs/delete", url.Values{"name": {"keep"}}, csrf, sess); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer POST /programs/delete = %d, ingin 403", rec.Code)
	}
	// Program harus tetap ada (viewer tak boleh menghapus).
	if _, err := st.GetProgram(context.Background(), "keep"); err != nil {
		t.Errorf("program terhapus oleh viewer yang seharusnya ditolak: %v", err)
	}
}
