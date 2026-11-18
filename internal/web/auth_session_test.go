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
			t.Errorf("must be valid: %q", l)
		}
	}
	for _, l := range bad {
		if validAuthHeaderLine(l) {
			t.Errorf("must be invalid: %q", l)
		}
	}
}

func TestClampHeaderForErrHidesValue(t *testing.T) {
	if got := clampHeaderForErr("Cookie: session=SECRET"); got != "Cookie" {
		t.Errorf("must be the name only; got %q", got)
	}
	if got := clampHeaderForErr("Cookie: session=SECRET"); strings.Contains(got, "SECRET") {
		t.Errorf("the value must not appear: %q", got)
	}
	// without ':' → a short slice, not the whole long string
	long := strings.Repeat("A", 40)
	if got := clampHeaderForErr(long); len(got) > 20 {
		t.Errorf("must be trimmed: %q", got)
	}
}

func TestHasSavedAuth(t *testing.T) {
	srv, _ := newTestServer(t)
	ctx := context.Background()
	if srv.hasSavedAuth(ctx, "prog") {
		t.Error("no session at first")
	}
	if err := srv.vault.Put(ctx, authSessionScope, "prog", []byte("Cookie: a=b")); err != nil {
		t.Fatal(err)
	}
	if !srv.hasSavedAuth(ctx, "prog") {
		t.Error("must be detected after Put")
	}
	if srv.hasSavedAuth(ctx, "other-program") {
		t.Error("another program must not be detected")
	}
}

// an authenticated scan MUST tick RoE; without it the scan is denied & the header value is
// never echoed to the response.
func TestScanAuthRoERequiredAndNoEcho(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := do(t, srv, "POST", "/scan", url.Values{
		"program": {"authprog"}, "in_scope": {"demo.test"}, "targets": {"demo.test"},
		"auth_headers": {"Cookie: session=SUPERSECRET"},
		// auth_roe deliberately not ticked
	})
	body := rec.Body.String()
	if !strings.Contains(body, "RoE") {
		t.Errorf("an authenticated scan without RoE must be denied:\n%s", body)
	}
	if strings.Contains(body, "SUPERSECRET") {
		t.Errorf("the header value leaked to the response:\n%s", body)
	}
	if srv.hasSavedAuth(context.Background(), "authprog") {
		t.Error("a denied scan must not save the session")
	}
}

// RoE + save_auth → the session is stored encrypted; then use_saved_auth uses it.
func TestScanAuthSaveAndReuse(t *testing.T) {
	srv, _ := newTestServer(t)
	ctx := context.Background()

	rec := do(t, srv, "POST", "/scan", url.Values{
		"program": {"authprog"}, "in_scope": {"demo.test"}, "targets": {"demo.test"},
		"auth_headers": {"Cookie: session=SECRETVAL"}, "auth_roe": {"1"}, "save_auth": {"1"},
	})
	if b := rec.Body.String(); strings.Contains(b, "RoE") || strings.Contains(b, "Invalid session header") {
		t.Fatalf("a valid authenticated scan must run:\n%s", b)
	}
	if !srv.hasSavedAuth(ctx, "authprog") {
		t.Fatal("the session must be stored in the vault")
	}
	raw, err := srv.vault.Reveal(ctx, authSessionScope, "authprog")
	if err != nil || !strings.Contains(string(raw), "session=SECRETVAL") {
		t.Fatalf("the stored session does not match: err=%v val=%q", err, raw)
	}

	// Use the stored session without pasting again → must not error.
	rec2 := do(t, srv, "POST", "/scan", url.Values{
		"program": {"authprog"}, "in_scope": {"demo.test"}, "targets": {"demo.test"},
		"use_saved_auth": {"1"}, "auth_roe": {"1"},
	})
	if b := rec2.Body.String(); strings.Contains(b, "RoE") || strings.Contains(b, "could not be read") {
		t.Errorf("using the stored session must succeed:\n%s", b)
	}
}
