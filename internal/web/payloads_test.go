package web

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"bughound/internal/audit"
	"bughound/internal/engine"
	"bughound/internal/engine/ffuf"
	"bughound/internal/engine/nuclei"
	"bughound/internal/finding"
	"bughound/internal/payload"
	"bughound/internal/recon"
	"bughound/internal/secret"
	"bughound/internal/store"
)

func seedCatalog(t *testing.T, st *store.Mem) {
	t.Helper()
	cat := payload.Catalog{
		BuiltAt: time.Now().UTC(),
		Sources: []payload.SourceInfo{
			{ID: "nuclei-official", Engine: "nuclei", Trust: payload.TrustTrusted, Count: 2, Enabled: 2, Available: true, Version: "v10.5.1"},
			{ID: "custom", Engine: "custom", Trust: payload.TrustReview, Count: 1, Enabled: 0, Available: true},
		},
		Entries: []payload.Entry{
			{TemplateID: "nuclei:ssrf-fetch", Source: "nuclei-official", Engine: "nuclei", Name: "SSRF via fetch", Type: "ssrf-fetch", SeverityDefault: finding.SeverityHigh, Tags: []string{"ssrf"}, Trust: payload.TrustTrusted, Version: "sha256:a", Enabled: true},
			{TemplateID: "nuclei:prometheus-metrics", Source: "nuclei-official", Engine: "nuclei", Name: "Prometheus Metrics", Type: "prometheus-metrics", SeverityDefault: finding.SeverityMedium, Tags: []string{"exposure"}, Trust: payload.TrustTrusted, Version: "sha256:b", Enabled: true},
			{TemplateID: "custom:open-redirect", Source: "custom", Engine: "custom", Name: "Open redirect", Type: "open-redirect", SeverityDefault: finding.SeverityLow, Trust: payload.TrustReview, Version: "sha256:c", Enabled: false},
		},
	}
	if err := st.ReplaceCatalog(context.Background(), cat); err != nil {
		t.Fatalf("seedCatalog: %v", err)
	}
}

func TestPayloads_RenderSeededCatalog(t *testing.T) {
	srv, st := newTestServer(t)
	seedCatalog(t, st)

	b := do(t, srv, "GET", "/payloads", nil).Body.String()
	for _, want := range []string{
		"Bank Payload",
		"nuclei:ssrf-fetch", "nuclei:prometheus-metrics", "custom:open-redirect",
		"semua <b>3</b>", // ringkasan total
		"trusted", "review", // badge trust di panel sumber
		"nuclei-official", // id sumber
	} {
		if !strings.Contains(b, want) {
			t.Errorf("halaman /payloads harus memuat %q", want)
		}
	}
}

func TestPayloads_Filter(t *testing.T) {
	srv, st := newTestServer(t)
	seedCatalog(t, st)

	b := do(t, srv, "GET", "/payloads?engine=custom", nil).Body.String()
	if !strings.Contains(b, "custom:open-redirect") {
		t.Errorf("filter engine=custom harus menampilkan entri custom")
	}
	if strings.Contains(b, "nuclei:ssrf-fetch") {
		t.Errorf("filter engine=custom tak boleh menampilkan entri nuclei")
	}
}

func TestPayloads_EmptyCatalog(t *testing.T) {
	srv, _ := newTestServer(t)
	b := do(t, srv, "GET", "/payloads", nil).Body.String()
	if !strings.Contains(b, "Bank Payload") {
		t.Errorf("halaman harus tetap render saat katalog kosong")
	}
}

// newPayloadServer: server AuthDisabled dengan sumber payload terkonfigurasi.
func newPayloadServer(t *testing.T, sources []payload.Source) (*Server, *store.Mem) {
	t.Helper()
	st := store.NewMem()
	k, _ := secret.NewRandomKey()
	srv, err := NewServer(Config{
		Store:          st,
		Engines:        []engine.Engine{nuclei.Mock{}, ffuf.Mock{}},
		Recon:          recon.MockPipeline{},
		Vault:          secret.NewMemVault(secret.NewKeyring(k)),
		Audit:          audit.NewMemLog([]byte("test-audit-key")),
		AuthDisabled:   true,
		PayloadSources: sources,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv, st
}

func TestPayloads_RefreshBuildsCatalog(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "http"), 0o755); err != nil {
		t.Fatal(err)
	}
	tmpl := "id: prometheus-metrics\ninfo:\n  name: Prometheus Metrics\n  severity: medium\n  tags: exposure\n"
	if err := os.WriteFile(filepath.Join(dir, "http", "p.yaml"), []byte(tmpl), 0o644); err != nil {
		t.Fatal(err)
	}

	srv, _ := newPayloadServer(t, []payload.Source{
		{ID: "nuclei-official", Engine: "nuclei", Kind: payload.KindNucleiDir, Path: dir, Trust: payload.TrustTrusted},
	})

	rec := do(t, srv, "POST", "/payloads/refresh", url.Values{})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /payloads/refresh = %d, ingin 303", rec.Code)
	}
	b := do(t, srv, "GET", "/payloads", nil).Body.String()
	if !strings.Contains(b, "nuclei:prometheus-metrics") {
		t.Errorf("setelah refresh, katalog harus memuat template hasil scan")
	}
	if !strings.Contains(b, "semua <b>1</b>") {
		t.Errorf("setelah refresh, total katalog harus 1")
	}
}

func TestPayloads_RefreshViewerForbidden(t *testing.T) {
	srv, _ := newRBACServer(t)
	csrf, sess := loginAs(t, srv, "view", "viewpw")
	if rec := authedReq(srv, "POST", "/payloads/refresh", url.Values{}, csrf, sess); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer POST /payloads/refresh = %d, ingin 403", rec.Code)
	}
}
