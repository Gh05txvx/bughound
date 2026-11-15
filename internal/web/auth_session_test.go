package web

import (
	"context"
	"net/url"
	"strings"
	"testing"
)

func TestValidAuthHeaderLine(t *testing.T) {
	ok := []string{"Cookie: session=abc", "Authorization: Bearer x.y.z", "X-Api-Key: 123"}
	bad := []string{"", "no-colon", "Cookie:", ": value", "two words: v"}
	for _, l := range ok {
		if !validAuthHeaderLine(l) {
			t.Errorf("harus valid: %q", l)
		}
	}
	for _, l := range bad {
		if validAuthHeaderLine(l) {
			t.Errorf("harus invalid: %q", l)
		}
	}
}

func TestClampHeaderForErrHidesValue(t *testing.T) {
	if got := clampHeaderForErr("Cookie: session=SECRET"); got != "Cookie" {
		t.Errorf("harus hanya nama; dapat %q", got)
	}
	if got := clampHeaderForErr("Cookie: session=SECRET"); strings.Contains(got, "SECRET") {
		t.Errorf("nilai tak boleh muncul: %q", got)
	}
	// tanpa ':' → potongan pendek, bukan seluruh string panjang
	long := strings.Repeat("A", 40)
	if got := clampHeaderForErr(long); len(got) > 20 {
		t.Errorf("harus dipotong: %q", got)
	}
}

func TestHasSavedAuth(t *testing.T) {
	srv, _ := newTestServer(t)
	ctx := context.Background()
	if srv.hasSavedAuth(ctx, "prog") {
		t.Error("awalnya tak ada sesi")
	}
	if err := srv.vault.Put(ctx, authSessionScope, "prog", []byte("Cookie: a=b")); err != nil {
		t.Fatal(err)
	}
	if !srv.hasSavedAuth(ctx, "prog") {
		t.Error("harus terdeteksi setelah Put")
	}
	if srv.hasSavedAuth(ctx, "program-lain") {
		t.Error("program lain tak boleh terdeteksi")
	}
}

// authenticated scan WAJIB mencentang RoE; tanpa itu ditolak & nilai header tak
// pernah ter-echo ke respons.
func TestScanAuthRoERequiredAndNoEcho(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := do(t, srv, "POST", "/scan", url.Values{
		"program": {"authprog"}, "in_scope": {"demo.test"}, "targets": {"demo.test"},
		"auth_headers": {"Cookie: session=SUPERSECRET"},
		// auth_roe sengaja tak dicentang
	})
	body := rec.Body.String()
	if !strings.Contains(body, "RoE") {
		t.Errorf("authenticated scan tanpa RoE harus ditolak:\n%s", body)
	}
	if strings.Contains(body, "SUPERSECRET") {
		t.Errorf("nilai header bocor ke respons:\n%s", body)
	}
	if srv.hasSavedAuth(context.Background(), "authprog") {
		t.Error("scan ditolak tak boleh menyimpan sesi")
	}
}

// RoE + save_auth → sesi tersimpan terenkripsi; lalu use_saved_auth memakainya.
func TestScanAuthSaveAndReuse(t *testing.T) {
	srv, _ := newTestServer(t)
	ctx := context.Background()

	rec := do(t, srv, "POST", "/scan", url.Values{
		"program": {"authprog"}, "in_scope": {"demo.test"}, "targets": {"demo.test"},
		"auth_headers": {"Cookie: session=SECRETVAL"}, "auth_roe": {"1"}, "save_auth": {"1"},
	})
	if b := rec.Body.String(); strings.Contains(b, "RoE") || strings.Contains(b, "tak sah") {
		t.Fatalf("scan terautentikasi valid harus jalan:\n%s", b)
	}
	if !srv.hasSavedAuth(ctx, "authprog") {
		t.Fatal("sesi harus tersimpan di vault")
	}
	raw, err := srv.vault.Reveal(ctx, authSessionScope, "authprog")
	if err != nil || !strings.Contains(string(raw), "session=SECRETVAL") {
		t.Fatalf("sesi tersimpan tak cocok: err=%v val=%q", err, raw)
	}

	// Pakai sesi tersimpan tanpa menempel ulang → tak boleh error.
	rec2 := do(t, srv, "POST", "/scan", url.Values{
		"program": {"authprog"}, "in_scope": {"demo.test"}, "targets": {"demo.test"},
		"use_saved_auth": {"1"}, "auth_roe": {"1"},
	})
	if b := rec2.Body.String(); strings.Contains(b, "RoE") || strings.Contains(b, "tak bisa dibaca") {
		t.Errorf("pakai sesi tersimpan harus sukses:\n%s", b)
	}
}
