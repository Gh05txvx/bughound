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

// TestServerRunHistoryPersistsAcrossRestart proves the NewServer wiring: the queue
// is backed by the store, so the run history survives a "restart" (a new server over the
// same store reloads the finished runs). This is what was lost before the
// persistence feature — each redeploy emptied the Processes panel.
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
	srv1.Close() // drain + finish() persists the terminal status to the store

	// "Restart": a new server over the SAME store.
	srv2, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer 2: %v", err)
	}
	t.Cleanup(func() { srv2.Close() })

	run, ok := srv2.queue.Get(id)
	if !ok {
		t.Fatal("the run history must be reloaded after a restart (the queue is not backed by the store?)")
	}
	if run.Status != jobs.Done {
		t.Errorf("reloaded status=%s, want done", run.Status)
	}
	if run.Summary.Saved != 2 || len(run.Summary.Scanned) != 1 {
		t.Errorf("the summary did not survive the restart: %+v", run.Summary)
	}
}
