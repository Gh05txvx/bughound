package store

import (
	"context"
	"testing"
	"time"

	"bughound/internal/jobs"
)

// TestRunStoreRoundTrip memverifikasi Mem & SQLite mengimplementasikan jobs.Store
// dengan benar: simpan (termasuk upsert), muat terurut terlama-dulu dengan Summary
// utuh, dan hapus.
func TestRunStoreRoundTrip(t *testing.T) {
	run := func(t *testing.T, st jobs.Store) {
		ctx := context.Background()
		base := time.Now().UTC().Truncate(time.Second)
		r1 := &jobs.Run{
			ID: "run_a", Program: "demo", Label: "scan 1", Status: jobs.Done,
			EnqueuedAt: base, StartedAt: base.Add(time.Second), FinishedAt: base.Add(2 * time.Second),
			Summary: jobs.Summary{Discovered: 5, Saved: 3, Duplicates: 1,
				Scanned: []string{"demo.test"}, Denied: []string{"evil.test — out-of-scope"}},
		}
		r2 := &jobs.Run{ID: "run_b", Program: "demo", Label: "scan 2", Status: jobs.Running,
			EnqueuedAt: base.Add(10 * time.Second)}

		if err := st.SaveRun(ctx, r1); err != nil {
			t.Fatal(err)
		}
		if err := st.SaveRun(ctx, r2); err != nil {
			t.Fatal(err)
		}

		got, err := st.LoadRuns(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 {
			t.Fatalf("muat %d run, ingin 2", len(got))
		}
		if got[0].ID != "run_a" || got[1].ID != "run_b" {
			t.Errorf("harus terlama dulu, dapat %s,%s", got[0].ID, got[1].ID)
		}
		if g := got[0]; g.Summary.Saved != 3 || g.Summary.Discovered != 5 || g.Summary.Duplicates != 1 ||
			len(g.Summary.Scanned) != 1 || len(g.Summary.Denied) != 1 {
			t.Errorf("Summary tak bertahan utuh: %+v", g.Summary)
		}
		if !got[0].FinishedAt.Equal(base.Add(2 * time.Second)) {
			t.Errorf("FinishedAt tak bertahan: %v", got[0].FinishedAt)
		}

		// Upsert: ubah status run_b.
		r2.Status = jobs.Done
		r2.FinishedAt = base.Add(20 * time.Second)
		if err := st.SaveRun(ctx, r2); err != nil {
			t.Fatal(err)
		}
		got, _ = st.LoadRuns(ctx)
		if len(got) != 2 {
			t.Fatalf("upsert tak boleh menambah baris, ada %d", len(got))
		}
		var b *jobs.Run
		for _, r := range got {
			if r.ID == "run_b" {
				b = r
			}
		}
		if b == nil || b.Status != jobs.Done {
			t.Errorf("upsert status gagal: %+v", b)
		}

		// Delete.
		if err := st.DeleteRun(ctx, "run_a"); err != nil {
			t.Fatal(err)
		}
		got, _ = st.LoadRuns(ctx)
		if len(got) != 1 || got[0].ID != "run_b" {
			t.Errorf("hapus gagal: %+v", got)
		}
		// Hapus id tak dikenal = no-op tanpa error.
		if err := st.DeleteRun(ctx, "tidak-ada"); err != nil {
			t.Errorf("hapus id asing harus no-op: %v", err)
		}
	}

	t.Run("Mem", func(t *testing.T) { run(t, NewMem()) })
	t.Run("SQLite", func(t *testing.T) {
		s, err := OpenSQLite(":memory:")
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		run(t, s)
	})
}
