package web

import (
	"context"
	"net/url"
	"strings"
	"testing"

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
