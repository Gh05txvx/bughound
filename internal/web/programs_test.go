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

	// Save a program through the scope editor.
	rec := do(t, srv, "POST", "/programs", url.Values{
		"name": {"acme"}, "in_scope": {"acme.io\n*.acme.io"}, "out_scope": {"admin.acme.io"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("save program = %d, want 303", rec.Code)
	}

	// Persistent in the store.
	p, err := st.GetProgram(ctx, "acme")
	if err != nil || len(p.InScope) != 2 || len(p.OutScope) != 1 {
		t.Fatalf("the program was not stored correctly: %+v (%v)", p, err)
	}

	// The program list shows it.
	if b := do(t, srv, "GET", "/programs", nil).Body.String(); !strings.Contains(b, "acme") {
		t.Error("the program list does not show 'acme'")
	}

	// The scan form prefills the scope from the stored program.
	if b := do(t, srv, "GET", "/scan?program=acme", nil).Body.String(); !strings.Contains(b, "*.acme.io") {
		t.Error("the scan form does not prefill the scope from the stored program")
	}

	// Preview: allow for in-scope, deny for out-of-scope.
	rec = do(t, srv, "POST", "/programs/preview", url.Values{
		"in_scope": {"acme.io\n*.acme.io"}, "out_scope": {"admin.acme.io"},
		"targets": {"app.acme.io\nadmin.acme.io\nevil.com"},
	})
	pb := rec.Body.String()
	if !strings.Contains(pb, "allow") || !strings.Contains(pb, "deny") {
		t.Errorf("the preview must show allow & deny:\n%s", pb)
	}

	// Fail-closed: an invalid scope entry is rejected on save (not 303).
	rec = do(t, srv, "POST", "/programs", url.Values{
		"name": {"bad"}, "in_scope": {"ok.io"}, "out_scope": {"a.*.io"},
	})
	if rec.Code == http.StatusSeeOther {
		t.Error("an invalid scope entry must be rejected (fail-closed), not saved")
	}
	if _, err := st.GetProgram(ctx, "bad"); err != store.ErrNotFound {
		t.Error("a program with an invalid scope must not be stored")
	}
}

func TestProgramDelete(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()

	// Create a program, make sure it shows in the list.
	do(t, srv, "POST", "/programs", url.Values{"name": {"delme"}, "in_scope": {"delme.test"}})
	if _, err := st.GetProgram(ctx, "delme"); err != nil {
		t.Fatalf("precondition: the program was not stored: %v", err)
	}
	if b := do(t, srv, "GET", "/programs", nil).Body.String(); !strings.Contains(b, "delme") {
		t.Fatal("precondition: the list does not show 'delme'")
	}

	// Delete → 303 to /programs?ok=deleted.
	rec := do(t, srv, "POST", "/programs/delete", url.Values{"name": {"delme"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("delete program = %d, want 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "ok=deleted") {
		t.Errorf("the redirect must carry ok=deleted, got %q", loc)
	}

	// The definition is gone from the store & list; the flash shows up.
	if _, err := st.GetProgram(ctx, "delme"); err != store.ErrNotFound {
		t.Errorf("the program must be deleted from the store, got %v", err)
	}
	body := do(t, srv, "GET", "/programs?ok=deleted", nil).Body.String()
	if strings.Contains(body, ">delme<") {
		t.Error("the list still shows 'delme' after delete")
	}
	if !strings.Contains(body, "Program deleted") {
		t.Error("the delete confirmation flash did not show")
	}

	// Idempotent: a repeated delete is still 303 (silent success), not 500.
	if rec := do(t, srv, "POST", "/programs/delete", url.Values{"name": {"delme"}}); rec.Code != http.StatusSeeOther {
		t.Errorf("repeated delete = %d, want 303 (idempotent)", rec.Code)
	}
}

func TestProgramDeleteViewerForbidden(t *testing.T) {
	srv, st := newRBACServer(t)
	// Seed one program directly in the store (not through a viewer).
	if err := st.SaveProgram(context.Background(), store.Program{Name: "keep", InScope: []string{"keep.test"}}); err != nil {
		t.Fatal(err)
	}
	csrf, sess := loginAs(t, srv, "view", "viewpw")
	if rec := authedReq(srv, "POST", "/programs/delete", url.Values{"name": {"keep"}}, csrf, sess); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer POST /programs/delete = %d, want 403", rec.Code)
	}
	// The program must stay (a viewer must not delete it).
	if _, err := st.GetProgram(context.Background(), "keep"); err != nil {
		t.Errorf("the program was deleted by a viewer that should have been denied: %v", err)
	}
}
