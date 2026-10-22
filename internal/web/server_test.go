package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"bughound/internal/engine/nuclei"
	"bughound/internal/finding"
	"bughound/internal/store"
)

func newTestServer(t *testing.T) (*Server, *store.Mem) {
	t.Helper()
	st := store.NewMem()
	srv, err := NewServer(st, nuclei.Mock{})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv, st
}

func do(t *testing.T, srv *Server, method, target string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	req := httptest.NewRequest(method, target, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func TestScanFormRenders(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := do(t, srv, "GET", "/scan", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /scan = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Konfigurasi scan") || !strings.Contains(body, "demo.test") {
		t.Error("form scan tidak ter-render dengan prefill")
	}
}

func TestStaticServed(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := do(t, srv, "GET", "/static/app.css", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /static/app.css = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "css") {
		t.Errorf("content-type css diharapkan, dapat %q", ct)
	}
}

func TestScanRunThenFindings(t *testing.T) {
	srv, st := newTestServer(t)

	rec := do(t, srv, "POST", "/scan", url.Values{
		"program":  {"demo"},
		"in_scope": {"demo.test"},
		"out_scope": {""},
		"targets":  {"demo.test\nevil.test"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /scan = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "temuan baru") || !strings.Contains(body, "evil.test") {
		t.Errorf("hasil scan tidak memuat ringkasan/penolakan:\n%s", body)
	}

	// Dua temuan tersimpan di store.
	fs, _ := st.List(context.Background(), store.Query{Program: "demo"})
	if len(fs) != 2 {
		t.Fatalf("ingin 2 temuan tersimpan, dapat %d", len(fs))
	}

	// Halaman findings menampilkannya.
	rec = do(t, srv, "GET", "/findings?program=demo", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "ssrf-via-fetch") {
		t.Errorf("findings tidak menampilkan temuan (code=%d)", rec.Code)
	}

	// Detail satu temuan: bukti tersensor, tanpa secret.
	id := fs[0].ID
	rec = do(t, srv, "GET", "/findings/"+id+"?program=demo", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET detail = %d", rec.Code)
	}
	d := rec.Body.String()
	if strings.Contains(d, "SECRET-abc123") {
		t.Error("detail membocorkan secret")
	}
}

func TestTriageConfirm(t *testing.T) {
	srv, st := newTestServer(t)
	do(t, srv, "POST", "/scan", url.Values{
		"program":  {"demo"},
		"in_scope": {"demo.test"},
		"targets":  {"demo.test"},
	})
	fs, _ := st.List(context.Background(), store.Query{Program: "demo"})
	if len(fs) == 0 {
		t.Fatal("tidak ada temuan untuk ditriase")
	}
	id := fs[0].ID

	rec := do(t, srv, "POST", "/findings/"+id+"/status", url.Values{
		"status":      {"confirmed"},
		"verified_by": {"gh05t"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST status = %d", rec.Code)
	}
	got, _ := st.Get(context.Background(), id)
	if got.Status != "confirmed" || got.VerifiedBy != "gh05t" {
		t.Errorf("triase tidak tersimpan: status=%s by=%s", got.Status, got.VerifiedBy)
	}

	// Triase manual tak boleh menetapkan duplicate.
	rec = do(t, srv, "POST", "/findings/"+id+"/status", url.Values{"status": {"duplicate"}})
	if rec.Code == http.StatusOK {
		t.Error("status duplicate lewat triase manual harus ditolak")
	}
}

// TestFindingsListsProgramFromStore mensimulasikan kondisi setelah restart:
// server baru (registry in-memory kosong), tapi data ada di store. Tab program
// harus tetap muncul dari store.
func TestFindingsListsProgramFromStore(t *testing.T) {
	st := store.NewMem()
	ctx := context.Background()
	f := &finding.Finding{
		Program: "demo", RunID: "r", Target: "https://demo.test",
		Type: "ssrf-via-fetch", Title: "SSRF", Severity: finding.SeverityHigh,
		Confidence: finding.ConfidenceMedium, Status: finding.StatusNew, SourceEngine: "nuclei",
		Location: finding.Location{URL: "https://demo.test/fetch"},
	}
	if _, err := st.Save(ctx, f); err != nil {
		t.Fatalf("seed Save: %v", err)
	}

	srv, err := NewServer(st, nuclei.Mock{}) // registry in-memory kosong
	if err != nil {
		t.Fatal(err)
	}
	rec := do(t, srv, "GET", "/findings", nil) // tanpa ?program=
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /findings = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "ssrf-via-fetch") || !strings.Contains(body, ">demo<") {
		t.Errorf("program dari store seharusnya tampil tanpa scan ulang:\n%s", body)
	}
}

func TestScanWithReconDiscovers(t *testing.T) {
	srv, st := newTestServer(t)
	rec := do(t, srv, "POST", "/scan", url.Values{
		"program":   {"demo"},
		"seeds":     {"demo.test"},
		"in_scope":  {"demo.test\n*.demo.test"},
		"out_scope": {"admin.demo.test"},
		"targets":   {""},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /scan = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "aset recon") {
		t.Error("hasil harus menampilkan jumlah aset recon")
	}
	if !strings.Contains(body, "exfil.evil.test") {
		t.Error("aset recon di luar scope harus muncul sebagai ditolak")
	}
	if fs, _ := st.List(context.Background(), store.Query{Program: "demo"}); len(fs) == 0 {
		t.Error("harus ada temuan dari aset recon yang in-scope")
	}
}
