package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"bughound/internal/audit"
	"bughound/internal/engine"
	"bughound/internal/engine/ffuf"
	"bughound/internal/engine/nuclei"
	"bughound/internal/finding"
	"bughound/internal/recon"
	"bughound/internal/secret"
	"bughound/internal/store"
)

func newTestServer(t *testing.T) (*Server, *store.Mem) {
	t.Helper()
	st := store.NewMem()
	k, _ := secret.NewRandomKey()
	srv, err := NewServer(Config{
		Store:        st,
		Engines:      []engine.Engine{nuclei.Mock{}, ffuf.Mock{}},
		Recon:        recon.MockPipeline{},
		Vault:        secret.NewMemVault(secret.NewKeyring(k)),
		Audit:        audit.NewMemLog([]byte("test-audit-key")),
		AuthDisabled: true, // fitur diuji tanpa gate login; RBAC diuji terpisah
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv, st
}

// runIDFrom mengekstrak run id dari partial status (id="run-...").
func runIDFrom(t *testing.T, body string) string {
	t.Helper()
	m := regexp.MustCompile(`id="run-([^"]+)"`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("run id tak ditemukan di respons:\n%s", body)
	}
	return m[1]
}

// waitRunDone menunggu run mencapai keadaan terminal lalu mengembalikan body-nya.
func waitRunDone(t *testing.T, srv *Server, id string) string {
	t.Helper()
	for i := 0; i < 300; i++ {
		b := do(t, srv, "GET", "/runs/"+id, nil).Body.String()
		if strings.Contains(b, "Lihat findings") || strings.Contains(b, "gagal") {
			return b
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("run tidak selesai tepat waktu")
	return ""
}

func do(t *testing.T, srv *Server, method, target string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	// Untuk permintaan state-changing, ambil token CSRF dulu (double-submit).
	var token string
	if method != http.MethodGet && method != http.MethodHead {
		gr := httptest.NewRecorder()
		srv.ServeHTTP(gr, httptest.NewRequest(http.MethodGet, "/scan", nil))
		for _, c := range gr.Result().Cookies() {
			if c.Name == csrfCookie {
				token = c.Value
			}
		}
	}
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
	if token != "" {
		req.AddCookie(&http.Cookie{Name: csrfCookie, Value: token})
		req.Header.Set("X-CSRF-Token", token)
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
		"program": {"demo"}, "in_scope": {"demo.test"}, "targets": {"demo.test\nevil.test"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /scan = %d", rec.Code)
	}
	done := waitRunDone(t, srv, runIDFrom(t, rec.Body.String()))
	if !strings.Contains(done, "temuan baru") || !strings.Contains(done, "evil.test") {
		t.Errorf("status run selesai tak memuat ringkasan/penolakan:\n%s", done)
	}

	fs, _ := st.List(context.Background(), store.Query{Program: "demo"})
	var hasNuclei, hasFfuf bool
	for _, f := range fs {
		switch f.SourceEngine {
		case "nuclei":
			hasNuclei = true
		case "ffuf":
			hasFfuf = true
		}
	}
	if !hasNuclei || !hasFfuf {
		t.Fatalf("kedua engine (nuclei+ffuf) harus menyumbang; dapat %d temuan", len(fs))
	}

	rec = do(t, srv, "GET", "/findings?program=demo", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "ssrf-via-fetch") {
		t.Errorf("findings tidak menampilkan temuan (code=%d)", rec.Code)
	}

	rec = do(t, srv, "GET", "/findings/"+fs[0].ID+"?program=demo", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET detail = %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "SECRET-abc123") {
		t.Error("detail membocorkan secret")
	}
}

func TestTriageConfirm(t *testing.T) {
	srv, st := newTestServer(t)
	rec0 := do(t, srv, "POST", "/scan", url.Values{
		"program": {"demo"}, "in_scope": {"demo.test"}, "targets": {"demo.test"},
	})
	waitRunDone(t, srv, runIDFrom(t, rec0.Body.String()))
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

	srv, err := NewServer(Config{ // registry in-memory kosong
		Store:        st,
		Engines:      []engine.Engine{nuclei.Mock{}},
		AuthDisabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
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
	done := waitRunDone(t, srv, runIDFrom(t, rec.Body.String()))
	if !strings.Contains(done, "aset recon") {
		t.Error("status run harus menampilkan jumlah aset recon")
	}
	if !strings.Contains(done, "exfil.evil.test") {
		t.Error("aset recon di luar scope harus muncul sebagai ditolak")
	}
	if fs, _ := st.List(context.Background(), store.Query{Program: "demo"}); len(fs) == 0 {
		t.Error("harus ada temuan dari aset recon yang in-scope")
	}
}

func TestReportFlow(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()

	rec0 := do(t, srv, "POST", "/scan", url.Values{
		"program": {"demo"}, "in_scope": {"demo.test"}, "targets": {"demo.test"},
	})
	waitRunDone(t, srv, runIDFrom(t, rec0.Body.String()))
	fs, _ := st.List(ctx, store.Query{Program: "demo"})
	if len(fs) == 0 {
		t.Fatal("tak ada temuan untuk direport")
	}

	// Sebelum ada yang dikonfirmasi: report kosong.
	rec := do(t, srv, "GET", "/report?program=demo", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Belum ada temuan") {
		t.Errorf("report tanpa confirmed harus empty state (code=%d)", rec.Code)
	}

	// Konfirmasi satu temuan.
	do(t, srv, "POST", "/findings/"+fs[0].ID+"/status", url.Values{"status": {"confirmed"}})

	rec = do(t, srv, "GET", "/report?program=demo", nil)
	body := rec.Body.String()
	if !strings.Contains(body, "DRAFT") || !strings.Contains(body, fs[0].Title) {
		t.Error("report harus memuat temuan terkonfirmasi dan ditandai DRAFT")
	}

	// Unduh .md.
	rec = do(t, srv, "GET", "/report/download?program=demo", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Content-Disposition"), "report-demo.md") {
		t.Errorf("unduh .md gagal: code=%d cd=%q", rec.Code, rec.Header().Get("Content-Disposition"))
	}
	if !strings.Contains(rec.Body.String(), "# Laporan") {
		t.Error("isi .md tidak sesuai")
	}

	// Tampilan cetak (untuk Simpan sebagai PDF).
	rec = do(t, srv, "GET", "/report/print?program=demo", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "window.print()") {
		t.Errorf("tampilan cetak gagal (code=%d)", rec.Code)
	}
}

func TestSettingsSecretFlow(t *testing.T) {
	srv, _ := newTestServer(t)

	rec := do(t, srv, "POST", "/settings/secrets", url.Values{
		"scope": {"global"}, "name": {"nuclei-key"}, "value": {"supersecret-xyz"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST add = %d, ingin 303", rec.Code)
	}

	rec = do(t, srv, "GET", "/settings?scope=global", nil)
	body := rec.Body.String()
	if !strings.Contains(body, "nuclei-key") {
		t.Error("secret harus terdaftar (nama)")
	}
	if strings.Contains(body, "supersecret-xyz") {
		t.Error("NILAI secret tidak boleh muncul di UI")
	}

	rec = do(t, srv, "POST", "/settings/secrets/delete", url.Values{
		"scope": {"global"}, "name": {"nuclei-key"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST delete = %d, ingin 303", rec.Code)
	}
	rec = do(t, srv, "GET", "/settings?scope=global", nil)
	if strings.Contains(rec.Body.String(), "nuclei-key") {
		t.Error("secret harus hilang setelah dihapus")
	}
}

func TestAuditTrail(t *testing.T) {
	srv, _ := newTestServer(t)

	rec := do(t, srv, "POST", "/scan", url.Values{
		"program": {"demo"}, "in_scope": {"demo.test"}, "targets": {"demo.test\nevil.test"},
	})
	waitRunDone(t, srv, runIDFrom(t, rec.Body.String()))

	rec = do(t, srv, "GET", "/audit?program=demo", nil)
	body := rec.Body.String()
	if !strings.Contains(body, "integritas OK") {
		t.Error("integritas audit harus OK")
	}
	if !strings.Contains(body, "scope.decision") {
		t.Error("audit harus memuat entri keputusan scope")
	}
	if !strings.Contains(body, "evil.test") {
		t.Error("penolakan evil.test harus tercatat di audit")
	}
}
