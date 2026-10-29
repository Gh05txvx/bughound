package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"bughound/internal/finding"
	"bughound/internal/payload"
)

// catalogStores mengembalikan setiap implementasi CatalogStore untuk diuji paritas.
func catalogStores(t *testing.T) map[string]CatalogStore {
	t.Helper()
	sq, err := OpenSQLite(filepath.Join(t.TempDir(), "catalog.db"))
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	t.Cleanup(func() { sq.Close() })
	return map[string]CatalogStore{"mem": NewMem(), "sqlite": sq}
}

func sampleCatalog() payload.Catalog {
	built := time.Date(2026, 10, 29, 10, 0, 0, 0, time.UTC)
	return payload.Catalog{
		BuiltAt: built,
		Sources: []payload.SourceInfo{
			{ID: "nuclei-official", Engine: "nuclei", Trust: payload.TrustTrusted, Count: 2, Enabled: 2, Available: true, UpdatedAt: built},
			{ID: "custom", Engine: "custom", Trust: payload.TrustReview, Count: 1, Enabled: 0, Available: true, UpdatedAt: built},
		},
		Entries: []payload.Entry{
			{TemplateID: "nuclei:ssrf-fetch", Source: "nuclei-official", Engine: "nuclei", Name: "SSRF via fetch", Type: "ssrf-fetch", SeverityDefault: finding.SeverityHigh, Tags: []string{"ssrf", "cloud"}, Trust: payload.TrustTrusted, Version: "sha256:aaa", Enabled: true},
			{TemplateID: "nuclei:prometheus-metrics", Source: "nuclei-official", Engine: "nuclei", Name: "Prometheus Metrics", Type: "prometheus-metrics", SeverityDefault: finding.SeverityMedium, Tags: []string{"exposure"}, Trust: payload.TrustTrusted, Version: "sha256:bbb", Enabled: true},
			{TemplateID: "custom:open-redirect", Source: "custom", Engine: "custom", Name: "Open redirect", Type: "open-redirect", SeverityDefault: finding.SeverityLow, Tags: []string{"redirect"}, Trust: payload.TrustReview, Version: "sha256:ccc", Enabled: false},
		},
	}
}

func TestCatalog_ReplaceAndStats(t *testing.T) {
	ctx := context.Background()
	for name, cs := range catalogStores(t) {
		t.Run(name, func(t *testing.T) {
			if err := cs.ReplaceCatalog(ctx, sampleCatalog()); err != nil {
				t.Fatalf("ReplaceCatalog: %v", err)
			}
			st, err := cs.CatalogStats(ctx)
			if err != nil {
				t.Fatalf("CatalogStats: %v", err)
			}
			if st.Total != 3 || st.Enabled != 2 {
				t.Errorf("total=%d enabled=%d, ingin 3/2", st.Total, st.Enabled)
			}
			if st.ByEngine["nuclei"] != 2 || st.ByEngine["custom"] != 1 {
				t.Errorf("byEngine=%v", st.ByEngine)
			}
			if st.ByTrust["trusted"] != 2 || st.ByTrust["review"] != 1 {
				t.Errorf("byTrust=%v", st.ByTrust)
			}
			if st.BySeverity["high"] != 1 || st.BySeverity["medium"] != 1 || st.BySeverity["low"] != 1 {
				t.Errorf("bySeverity=%v", st.BySeverity)
			}
			if !st.BuiltAt.Equal(time.Date(2026, 10, 29, 10, 0, 0, 0, time.UTC)) {
				t.Errorf("builtAt=%v", st.BuiltAt)
			}
		})
	}
}

func TestCatalog_ReplaceIsAtomicSwap(t *testing.T) {
	ctx := context.Background()
	for name, cs := range catalogStores(t) {
		t.Run(name, func(t *testing.T) {
			if err := cs.ReplaceCatalog(ctx, sampleCatalog()); err != nil {
				t.Fatal(err)
			}
			// Refresh kedua dengan katalog lebih kecil harus MENGGANTI, bukan menambah.
			smaller := payload.Catalog{
				BuiltAt: time.Now().UTC(),
				Entries: []payload.Entry{{TemplateID: "nuclei:only-one", Source: "nuclei-official", Engine: "nuclei", Name: "Only", Type: "only-one", SeverityDefault: finding.SeverityInfo, Trust: payload.TrustTrusted, Version: "sha256:z", Enabled: true}},
				Sources: []payload.SourceInfo{{ID: "nuclei-official", Engine: "nuclei", Trust: payload.TrustTrusted, Count: 1, Enabled: 1, Available: true}},
			}
			if err := cs.ReplaceCatalog(ctx, smaller); err != nil {
				t.Fatal(err)
			}
			st, _ := cs.CatalogStats(ctx)
			if st.Total != 1 {
				t.Errorf("total setelah swap=%d, ingin 1 (katalog lama harus terganti)", st.Total)
			}
			srcs, _ := cs.ListCatalogSources(ctx)
			if len(srcs) != 1 {
				t.Errorf("sumber setelah swap=%d, ingin 1", len(srcs))
			}
		})
	}
}

func TestCatalog_ListFilters(t *testing.T) {
	ctx := context.Background()
	for name, cs := range catalogStores(t) {
		t.Run(name, func(t *testing.T) {
			if err := cs.ReplaceCatalog(ctx, sampleCatalog()); err != nil {
				t.Fatal(err)
			}
			cases := []struct {
				q    CatalogQuery
				want int
			}{
				{CatalogQuery{}, 3},
				{CatalogQuery{Engine: "nuclei"}, 2},
				{CatalogQuery{Trust: "review"}, 1},
				{CatalogQuery{Severity: "high"}, 1},
				{CatalogQuery{Enabled: "1"}, 2},
				{CatalogQuery{Enabled: "0"}, 1},
				{CatalogQuery{Tag: "ssrf"}, 1},
				{CatalogQuery{Tag: "exposure"}, 1},
				{CatalogQuery{Search: "redirect"}, 1},   // cocok nama & id
				{CatalogQuery{Search: "PROMETHEUS"}, 1},  // case-insensitive
				{CatalogQuery{Engine: "nuclei", Enabled: "1"}, 2},
			}
			for _, c := range cases {
				got, total, err := cs.ListCatalog(ctx, c.q)
				if err != nil {
					t.Fatalf("ListCatalog(%+v): %v", c.q, err)
				}
				if total != c.want || len(got) != c.want {
					t.Errorf("ListCatalog(%+v) total=%d len=%d, ingin %d", c.q, total, len(got), c.want)
				}
			}
			// Urutan: severity terberat dulu (high, medium, low).
			got, _, _ := cs.ListCatalog(ctx, CatalogQuery{})
			if got[0].SeverityDefault != finding.SeverityHigh || got[2].SeverityDefault != finding.SeverityLow {
				t.Errorf("urutan severity salah: %s..%s", got[0].SeverityDefault, got[2].SeverityDefault)
			}
		})
	}
}

func TestCatalog_Pagination(t *testing.T) {
	ctx := context.Background()
	for name, cs := range catalogStores(t) {
		t.Run(name, func(t *testing.T) {
			if err := cs.ReplaceCatalog(ctx, sampleCatalog()); err != nil {
				t.Fatal(err)
			}
			got, total, err := cs.ListCatalog(ctx, CatalogQuery{Limit: 2, Offset: 0})
			if err != nil {
				t.Fatal(err)
			}
			if total != 3 || len(got) != 2 {
				t.Errorf("hal 1: total=%d len=%d, ingin 3/2", total, len(got))
			}
			got2, _, _ := cs.ListCatalog(ctx, CatalogQuery{Limit: 2, Offset: 2})
			if len(got2) != 1 {
				t.Errorf("hal 2: len=%d, ingin 1", len(got2))
			}
			if got[0].TemplateID == got2[0].TemplateID {
				t.Errorf("paginasi tumpang tindih: %s", got[0].TemplateID)
			}
		})
	}
}
