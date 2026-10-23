package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"bughound/internal/audit"
	"bughound/internal/engine"
	"bughound/internal/engine/nuclei"
	"bughound/internal/secret"
	"bughound/internal/store"
)

// Pengujian audit (BH-P03-APPSEC): nilai secret yang tersimpan tidak boleh
// pernah muncul di endpoint mana pun (findings, report, audit, settings, scan).
func TestAudit_SecretNeverLeaksAcrossEndpoints(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()
	const canary = "LEAK-CANARY-9z8y7x"

	// Simpan secret lewat Settings.
	if rec := do(t, srv, "POST", "/settings/secrets", url.Values{
		"scope": {"global"}, "name": {"engine-token"}, "value": {canary},
	}); rec.Code != 303 {
		t.Fatalf("simpan secret = %d", rec.Code)
	}

	// Jalankan scan + konfirmasi + report (jalur yang paling mungkin membocorkan).
	rec := do(t, srv, "POST", "/scan", url.Values{
		"program": {"demo"}, "in_scope": {"demo.test"}, "targets": {"demo.test"},
	})
	waitRunDone(t, srv, runIDFrom(t, rec.Body.String()))
	fs, _ := st.List(ctx, store.Query{Program: "demo"})
	if len(fs) > 0 {
		do(t, srv, "POST", "/findings/"+fs[0].ID+"/status", url.Values{"status": {"confirmed"}})
	}

	endpoints := []string{
		"/settings?scope=global",
		"/findings?program=demo",
		"/report?program=demo",
		"/report/download?program=demo",
		"/report/print?program=demo",
		"/audit?program=demo",
		"/scan",
	}
	for _, ep := range endpoints {
		body := do(t, srv, "GET", ep, nil).Body.String()
		if strings.Contains(body, canary) {
			t.Errorf("KEBOCORAN: nilai secret muncul di %s", ep)
		}
	}
}

// Audit trail harus tetap utuh (Verify OK) setelah banyak operasi.
func TestAudit_TrailIntegrityAfterManyOps(t *testing.T) {
	srv, _ := newTestServer(t)
	for i := 0; i < 3; i++ {
		rec := do(t, srv, "POST", "/scan", url.Values{
			"program": {"demo"}, "in_scope": {"demo.test"}, "out_scope": {"admin.demo.test"},
			"targets": {"demo.test\nevil.test\nadmin.demo.test"},
		})
		waitRunDone(t, srv, runIDFrom(t, rec.Body.String()))
	}
	body := do(t, srv, "GET", "/audit?program=demo", nil).Body.String()
	if !strings.Contains(body, "integritas OK") {
		t.Error("audit trail harus tetap terverifikasi utuh setelah banyak run")
	}
	if strings.Contains(body, "INTEGRITAS RUSAK") {
		t.Error("audit trail tidak boleh rusak")
	}
}

// Remediasi BH-F01: POST tanpa token CSRF / lintas-situs harus ditolak.
func TestAudit_CSRFBlocksForgedPost(t *testing.T) {
	srv, _ := newTestServer(t)
	form := url.Values{"program": {"x"}, "in_scope": {"demo.test"}, "targets": {"demo.test"}}

	// Tanpa cookie & token -> 403.
	req := httptest.NewRequest("POST", "/scan", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST tanpa CSRF harus 403, dapat %d", rec.Code)
	}

	// Token valid tapi Sec-Fetch-Site: cross-site -> tetap 403.
	gr := httptest.NewRecorder()
	srv.ServeHTTP(gr, httptest.NewRequest("GET", "/scan", nil))
	var tok string
	for _, c := range gr.Result().Cookies() {
		if c.Name == csrfCookie {
			tok = c.Value
		}
	}
	req2 := httptest.NewRequest("POST", "/scan", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.AddCookie(&http.Cookie{Name: csrfCookie, Value: tok})
	req2.Header.Set("X-CSRF-Token", tok)
	req2.Header.Set("Sec-Fetch-Site", "cross-site")
	rec2 := httptest.NewRecorder()
	srv.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("POST lintas-situs harus 403, dapat %d", rec2.Code)
	}
}

// Regresi: form POST non-HTMX yang SAH memakai token di field + `Origin: null`
// (dikirim Chromium untuk navigasi form same-origin di bawah Referrer-Policy:
// no-referrer) harus DITERIMA. Sebelum perbaikan, Origin "null" dianggap
// mismatch dan menolak semua form non-HTMX. Pertahanan tetap: token wajib &
// lintas-situs tetap ditolak.
func TestAudit_CSRFFormFieldNullOriginAccepted(t *testing.T) {
	srv, st := newTestServer(t)

	// Ambil cookie token dari GET.
	gr := httptest.NewRecorder()
	srv.ServeHTTP(gr, httptest.NewRequest("GET", "/programs/edit", nil))
	var tok string
	for _, c := range gr.Result().Cookies() {
		if c.Name == csrfCookie {
			tok = c.Value
		}
	}
	if tok == "" {
		t.Fatal("tidak dapat token CSRF dari GET")
	}
	form := url.Values{"name": {"csrfnull"}, "in_scope": {"demo.test"}}

	// Token di FIELD body (bukan header) + Origin: null + same-origin -> 303.
	req := httptest.NewRequest("POST", "/programs", strings.NewReader(addField(form, "csrf", tok).Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookie, Value: tok})
	req.Header.Set("Origin", "null")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("form POST sah (Origin: null) harus 303, dapat %d", rec.Code)
	}
	if _, err := st.GetProgram(context.Background(), "csrfnull"); err != nil {
		t.Fatalf("program harus tersimpan setelah POST diterima: %v", err)
	}

	// Token SALAH + Origin: null -> tetap 403 (token tetap wajib).
	bad := httptest.NewRequest("POST", "/programs", strings.NewReader(addField(form, "csrf", "salah").Encode()))
	bad.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	bad.AddCookie(&http.Cookie{Name: csrfCookie, Value: tok})
	bad.Header.Set("Origin", "null")
	badRec := httptest.NewRecorder()
	srv.ServeHTTP(badRec, bad)
	if badRec.Code != http.StatusForbidden {
		t.Fatalf("token salah (Origin: null) harus tetap 403, dapat %d", badRec.Code)
	}

	// Origin: null + Sec-Fetch-Site: cross-site -> tetap 403 (lintas-situs ditolak).
	xs := httptest.NewRequest("POST", "/programs", strings.NewReader(addField(form, "csrf", tok).Encode()))
	xs.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	xs.AddCookie(&http.Cookie{Name: csrfCookie, Value: tok})
	xs.Header.Set("Origin", "null")
	xs.Header.Set("Sec-Fetch-Site", "cross-site")
	xsRec := httptest.NewRecorder()
	srv.ServeHTTP(xsRec, xs)
	if xsRec.Code != http.StatusForbidden {
		t.Fatalf("lintas-situs (Origin: null) harus 403, dapat %d", xsRec.Code)
	}
}

// addField mengembalikan salinan v dengan satu field tambahan.
func addField(v url.Values, k, val string) url.Values {
	out := url.Values{}
	for kk, vv := range v {
		out[kk] = append([]string(nil), vv...)
	}
	out.Set(k, val)
	return out
}

// Remediasi BH-F01: HTTP Basic auth saat AuthSecret diset.
func TestAudit_BasicAuthEnforced(t *testing.T) {
	st := store.NewMem()
	k, _ := secret.NewRandomKey()
	srv, err := NewServer(Config{
		Store:      st,
		Engines:    []engine.Engine{nuclei.Mock{}},
		Vault:      secret.NewMemVault(secret.NewKeyring(k)),
		Audit:      audit.NewMemLog([]byte("k")),
		AuthSecret: "s3kret",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })

	// Tanpa kredensial -> 401.
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/scan", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("tanpa auth harus 401, dapat %d", rec.Code)
	}
	// Password benar -> 200.
	req := httptest.NewRequest("GET", "/scan", nil)
	req.SetBasicAuth("x", "s3kret")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("auth benar harus 200, dapat %d", rec.Code)
	}
	// Password salah -> 401.
	req = httptest.NewRequest("GET", "/scan", nil)
	req.SetBasicAuth("x", "salah")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("password salah harus 401, dapat %d", rec.Code)
	}
}
