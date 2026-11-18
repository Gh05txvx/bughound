package store

import (
	"context"
	"errors"
	"testing"
)

func TestAIStore_Mem(t *testing.T)    { runAIStoreTests(t, NewMem()) }
func TestAIStore_SQLite(t *testing.T) {
	st, err := OpenSQLite(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	runAIStoreTests(t, st)
}

func runAIStoreTests(t *testing.T, as AIStore) {
	t.Helper()
	ctx := context.Background()

	// Setting: empty by default, round-trip, overwrite.
	if v, _ := as.GetSetting(ctx, "ai_model"); v != "" {
		t.Fatalf("the initial setting must be empty, got %q", v)
	}
	if err := as.PutSetting(ctx, "ai_model", "claude-sonnet-5-5"); err != nil {
		t.Fatal(err)
	}
	if v, _ := as.GetSetting(ctx, "ai_model"); v != "claude-sonnet-5-5" {
		t.Fatalf("GetSetting = %q", v)
	}
	_ = as.PutSetting(ctx, "ai_model", "claude-haiku-5-5")
	if v, _ := as.GetSetting(ctx, "ai_model"); v != "claude-haiku-5-5" {
		t.Fatalf("overwriting the setting failed: %q", v)
	}

	// Analysis: missing → ErrNotFound.
	if _, err := as.GetAIAnalysis(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing must be ErrNotFound, got %v", err)
	}

	// Put + Get round-trip.
	a := AIAnalysis{FindingID: "f1", Program: "p1", Model: "claude-sonnet-5-5", SourceHash: "h1", Payload: `{"why":"x"}`}
	if err := as.PutAIAnalysis(ctx, a); err != nil {
		t.Fatal(err)
	}
	got, err := as.GetAIAnalysis(ctx, "f1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Program != "p1" || got.Model != "claude-sonnet-5-5" || got.SourceHash != "h1" || got.Payload != `{"why":"x"}` {
		t.Fatalf("wrong round-trip: %+v", got)
	}
	if got.CreatedAt.IsZero() {
		t.Fatal("created_at must be filled in automatically")
	}

	// Overwrite (new hash).
	a.SourceHash, a.Payload = "h2", `{"why":"y"}`
	_ = as.PutAIAnalysis(ctx, a)
	got, _ = as.GetAIAnalysis(ctx, "f1")
	if got.SourceHash != "h2" || got.Payload != `{"why":"y"}` {
		t.Fatalf("overwrite failed: %+v", got)
	}

	// Delete per program.
	_ = as.PutAIAnalysis(ctx, AIAnalysis{FindingID: "f2", Program: "p1", Model: "m", SourceHash: "h", Payload: "{}"})
	_ = as.PutAIAnalysis(ctx, AIAnalysis{FindingID: "f3", Program: "p2", Model: "m", SourceHash: "h", Payload: "{}"})
	n, err := as.DeleteAIAnalysisByProgram(ctx, "p1")
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("deleted p1 = %d, want 2", n)
	}
	if _, err := as.GetAIAnalysis(ctx, "f1"); !errors.Is(err, ErrNotFound) {
		t.Fatal("f1 should be deleted")
	}
	if _, err := as.GetAIAnalysis(ctx, "f3"); err != nil {
		t.Fatal("f3 (p2) must not be deleted")
	}
}
