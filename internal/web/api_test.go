package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"bughound/internal/finding"
	"bughound/internal/store"
)

// seedAPIFinding menyimpan satu temuan (lengkap dengan evidence.request) dan
// mengembalikan id yang diberikan store — dipakai untuk menguji API JSON.
func seedAPIFinding(t *testing.T, st *store.Mem, program, locURL, request string, sev finding.Severity) string {
	t.Helper()
	res, err := st.Save(context.Background(), &finding.Finding{
		Program:      program,
		RunID:        "run1",
		Target:       "https://" + program + ".test",
		Type:         "sqli",
		Title:        "SQLi di " + locURL,
		Severity:     sev,
		Confidence:   finding.ConfidenceMedium,
		Status:       finding.StatusNew,
		SourceEngine: "nuclei-dast",
		Location:     finding.Location{URL: locURL, Method: "GET", Parameter: "q"},
		Evidence:     &finding.Evidence{Request: request},
	})
	if err != nil {
		t.Fatalf("seed Save: %v", err)
	}
	return res.ID
}

// TestAPIFindingsList: daftar temuan satu program dalam JSON, termasuk
// evidence.request, dan tidak membocorkan program lain.
func TestAPIFindingsList(t *testing.T) {
	srv, st := newTestServer(t)
	id := seedAPIFinding(t, st, "acme", "https://acme.io/rest/products/search?q=x",
		"GET /rest/products/search?q=x' HTTP/1.1\r\nHost: acme.io\r\n\r\n", finding.SeverityCritical)
	seedAPIFinding(t, st, "acme", "https://acme.io/b", "GET /b HTTP/1.1\r\n\r\n", finding.SeverityLow)
	seedAPIFinding(t, st, "globex", "https://globex.io/c", "GET /c HTTP/1.1\r\n\r\n", finding.SeverityHigh)

	rec := do(t, srv, "GET", "/api/v1/findings?program=acme", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET list = %d, body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, ingin application/json", ct)
	}
	var resp apiFindingsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v — body=%s", err, rec.Body.String())
	}
	if resp.Count != 2 || len(resp.Findings) != 2 {
		t.Fatalf("count=%d findings=%d, ingin 2 (hanya program acme)", resp.Count, len(resp.Findings))
	}
	var sawRequest bool
	for _, f := range resp.Findings {
		if f.Program != "acme" {
			t.Errorf("temuan program lain bocor: %s", f.Program)
		}
		if f.ID == id {
			if f.Evidence != nil && strings.Contains(f.Evidence.Request, "products/search") {
				sawRequest = true
			}
		}
	}
	if !sawRequest {
		t.Error("evidence.request tidak terbawa di JSON daftar (dibutuhkan extension Burp)")
	}
}

// TestAPIFindingsProgramRequired: tanpa ?program= → 400 JSON.
func TestAPIFindingsProgramRequired(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := do(t, srv, "GET", "/api/v1/findings", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("tanpa program = %d, ingin 400", rec.Code)
	}
	var e apiError
	if json.Unmarshal(rec.Body.Bytes(), &e); e.Error == "" {
		t.Error("galat JSON kosong")
	}
}

// TestAPIFindingsInvalidFilter: status/severity asing ditolak (400), tidak
// diam-diam diabaikan — konsisten default-deny.
func TestAPIFindingsInvalidFilter(t *testing.T) {
	srv, st := newTestServer(t)
	seedAPIFinding(t, st, "acme", "https://acme.io/a", "GET /a HTTP/1.1\r\n\r\n", finding.SeverityHigh)
	for _, qs := range []string{"program=acme&status=bogus", "program=acme&severity=whatever"} {
		rec := do(t, srv, "GET", "/api/v1/findings?"+qs, nil)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%q = %d, ingin 400", qs, rec.Code)
		}
	}
}

// TestAPIFindingsStatusFilter: filter status yang sah benar-benar menyaring.
func TestAPIFindingsStatusFilter(t *testing.T) {
	srv, st := newTestServer(t)
	seedAPIFinding(t, st, "acme", "https://acme.io/a", "GET /a HTTP/1.1\r\n\r\n", finding.SeverityHigh)
	seedAPIFinding(t, st, "acme", "https://acme.io/b", "GET /b HTTP/1.1\r\n\r\n", finding.SeverityLow)

	rec := do(t, srv, "GET", "/api/v1/findings?program=acme&status=confirmed", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("filter status = %d", rec.Code)
	}
	var resp apiFindingsResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Count != 0 {
		t.Errorf("status=confirmed = %d temuan, ingin 0 (semua masih new)", resp.Count)
	}
}

// TestAPIFindingDetail: ambil satu temuan by id; id asing → 404.
func TestAPIFindingDetail(t *testing.T) {
	srv, st := newTestServer(t)
	id := seedAPIFinding(t, st, "acme", "https://acme.io/x?q=1",
		"GET /x?q=1' HTTP/1.1\r\nHost: acme.io\r\n\r\n", finding.SeverityCritical)

	rec := do(t, srv, "GET", "/api/v1/findings/"+id, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("detail = %d, body=%s", rec.Code, rec.Body.String())
	}
	var f finding.Finding
	if err := json.Unmarshal(rec.Body.Bytes(), &f); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if f.ID != id {
		t.Errorf("id = %q, ingin %q", f.ID, id)
	}
	if f.Evidence == nil || !strings.Contains(f.Evidence.Request, "/x?q=1") {
		t.Error("evidence.request hilang di detail")
	}

	rec404 := do(t, srv, "GET", "/api/v1/findings/tidak-ada", nil)
	if rec404.Code != http.StatusNotFound {
		t.Errorf("id asing = %d, ingin 404", rec404.Code)
	}
}

// TestBurpPage: halaman onboarding integrasi Burp ter-render dengan konten inti,
// dan contoh perintah memakai program nyata dari store.
func TestBurpPage(t *testing.T) {
	srv, st := newTestServer(t)
	seedAPIFinding(t, st, "acme", "https://acme.io/a", "GET /a HTTP/1.1\r\n\r\n", finding.SeverityHigh)

	rec := do(t, srv, "GET", "/burp", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /burp = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"Integrasi Burp", "/api/v1/findings", "gradle shadowJar", "Community", "Kirim ke Repeater"} {
		if !strings.Contains(body, want) {
			t.Errorf("halaman /burp tak memuat %q", want)
		}
	}
	if !strings.Contains(body, "program=acme") {
		t.Error("contoh perintah tidak memakai program nyata dari store")
	}
}

// TestAPIRequiresAuth membuktikan endpoint API terlindungi front controller yang
// sama: tanpa kredensial → 401 JSON (BUKAN redirect 302 ke /login, yang akan
// membingungkan klien mesin), dan HTTP Basic yang sah → 200. Inilah jalur yang
// dipakai extension Burp (auth otomasi yang memang sudah ada di tool).
func TestAPIRequiresAuth(t *testing.T) {
	srv, st := newAuthServer(t, "admin", "s3kret-pass")
	seedAPIFinding(t, st, "acme", "https://acme.io/a", "GET /a HTTP/1.1\r\n\r\n", finding.SeverityHigh)
	const target = "/api/v1/findings?program=acme"

	// Tanpa kredensial → 401 JSON, tidak boleh redirect.
	noauth := httptest.NewRecorder()
	srv.ServeHTTP(noauth, httptest.NewRequest("GET", target, nil))
	if noauth.Code != http.StatusUnauthorized {
		t.Fatalf("tanpa auth = %d, ingin 401 (bukan redirect %d)", noauth.Code, http.StatusFound)
	}
	if ct := noauth.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("galat auth Content-Type = %q, ingin JSON", ct)
	}

	// HTTP Basic sah → 200.
	ok := httptest.NewRecorder()
	rok := httptest.NewRequest("GET", target, nil)
	rok.SetBasicAuth("admin", "s3kret-pass")
	srv.ServeHTTP(ok, rok)
	if ok.Code != http.StatusOK {
		t.Fatalf("Basic sah = %d, ingin 200, body=%s", ok.Code, ok.Body.String())
	}

	// Basic salah → 401.
	bad := httptest.NewRecorder()
	rbad := httptest.NewRequest("GET", target, nil)
	rbad.SetBasicAuth("admin", "salah")
	srv.ServeHTTP(bad, rbad)
	if bad.Code != http.StatusUnauthorized {
		t.Errorf("Basic salah = %d, ingin 401", bad.Code)
	}
}
