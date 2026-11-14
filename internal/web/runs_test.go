package web

import (
	"context"
	"testing"

	"bughound/internal/audit"
	"bughound/internal/engine"
	"bughound/internal/engine/ffuf"
	"bughound/internal/engine/nuclei"
	"bughound/internal/jobs"
	"bughound/internal/recon"
	"bughound/internal/secret"
	"bughound/internal/store"
)

// TestServerRunHistoryPersistsAcrossRestart membuktikan wiring NewServer: queue
// di-back store, sehingga riwayat run selamat dari "restart" (server baru atas
// store yang sama memuat ulang run yang sudah selesai). Ini yang hilang sebelum
// fitur persistensi — tiap redeploy mengosongkan panel Proses.
func TestServerRunHistoryPersistsAcrossRestart(t *testing.T) {
	st := store.NewMem()
	k, _ := secret.NewRandomKey()
	cfg := Config{
		Store:        st,
		Engines:      []engine.Engine{nuclei.Mock{}, ffuf.Mock{}},
		Recon:        recon.MockPipeline{},
		Vault:        secret.NewMemVault(secret.NewKeyring(k)),
		Audit:        audit.NewMemLog([]byte("test-audit-key")),
		AuthDisabled: true,
	}

	srv1, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer 1: %v", err)
	}
	id := srv1.queue.Enqueue("demo", "scan demo.test", func(context.Context, string) (jobs.Summary, error) {
		return jobs.Summary{Saved: 2, Scanned: []string{"demo.test"}}, nil
	})
	srv1.Close() // menguras + finish() mem-persist status terminal ke store

	// "Restart": server baru di atas store yang SAMA.
	srv2, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer 2: %v", err)
	}
	t.Cleanup(func() { srv2.Close() })

	run, ok := srv2.queue.Get(id)
	if !ok {
		t.Fatal("riwayat run harus dimuat ulang setelah restart (queue tak di-back store?)")
	}
	if run.Status != jobs.Done {
		t.Errorf("status dimuat ulang=%s, ingin done", run.Status)
	}
	if run.Summary.Saved != 2 || len(run.Summary.Scanned) != 1 {
		t.Errorf("summary tak bertahan lintas-restart: %+v", run.Summary)
	}
}
