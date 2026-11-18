package audit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openAnchored(t *testing.T) (*SQLiteLog, string) {
	t.Helper()
	dir := t.TempDir()
	anchorPath := filepath.Join(dir, "a.anchor")
	l, err := OpenSQLiteLog(filepath.Join(dir, "a.db"), testKey, WithAnchorer(NewFileAnchorer(anchorPath, testKey)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l, anchorPath
}

func TestAnchorVerifyOK(t *testing.T) {
	l, anchorPath := openAnchored(t)
	appendN(t, l, 3)
	res, err := l.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Count != 3 || res.Anchors != 3 {
		t.Fatalf("verify must be OK with 3 entries + 3 anchors; got %+v", res)
	}
	b, _ := os.ReadFile(anchorPath)
	if n := strings.Count(strings.TrimSpace(string(b)), "\n") + 1; n != 3 {
		t.Fatalf("the anchor file must have 3 lines; got %d", n)
	}
}

// The core of BH-F06: the internal chain accepts an empty log (valid), but a
// surviving anchor reveals that the WHOLE store was deleted.
func TestAnchorDetectsWholesaleDeletion(t *testing.T) {
	l, _ := openAnchored(t)
	appendN(t, l, 3)

	// Verifying the chain alone over 0 entries would say "OK". Show first that
	// this is the gap: delete every row outside the application.
	if _, err := l.db.Exec(`DELETE FROM audit_log`); err != nil {
		t.Fatal(err)
	}
	res, _ := l.Verify(context.Background())
	if res.OK {
		t.Fatal("deleting the WHOLE log must be detected through the anchor")
	}
	if !strings.Contains(res.Reason, "deleted") && !strings.Contains(res.Reason, "truncated") {
		t.Fatalf("the reason must mention deletion or truncation; got %q", res.Reason)
	}
}

func TestAnchorDetectsTruncation(t *testing.T) {
	l, _ := openAnchored(t)
	appendN(t, l, 5)
	// Tail truncation: leaves a prefix (seq 1..2) that is valid as a chain.
	if _, err := l.db.Exec(`DELETE FROM audit_log WHERE seq > 2`); err != nil {
		t.Fatal(err)
	}
	res, _ := l.Verify(context.Background())
	if res.OK {
		t.Fatal("tail truncation must be detected through the anchor (the prefix is still valid)")
	}
	if res.BrokenAt != 3 {
		t.Fatalf("must break at anchor seq 3; got %+v", res)
	}
}

// Rollback: the store is replaced with another valid chain (different hashes)
// while the old anchor survives → the head hash mismatch is detected.
func TestAnchorDetectsRollback(t *testing.T) {
	dir := t.TempDir()
	anchorPath := filepath.Join(dir, "a.anchor")
	an := NewFileAnchorer(anchorPath, testKey)
	// A legitimate anchor (correct tag) for seq 1, but the hash does NOT belong to a real entry.
	if err := an.WriteAnchor(Anchor{Seq: 1, Hash: "cafebabe", At: time.Unix(0, 0).UTC()}); err != nil {
		t.Fatal(err)
	}
	l, err := OpenSQLiteLog(filepath.Join(dir, "a.db"), testKey, WithAnchorer(an))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	appendN(t, l, 1) // a real entry at seq 1 with hash != cafebabe
	res, _ := l.Verify(context.Background())
	if res.OK {
		t.Fatal("a head hash vs anchor mismatch (rollback) must be detected")
	}
}

func TestAnchorDetectsForgedAnchorFile(t *testing.T) {
	l, anchorPath := openAnchored(t)
	appendN(t, l, 2)
	// Insert an anchor with a forged tag (as if the anchor file had been tampered with).
	f, err := os.OpenFile(anchorPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(`{"seq":2,"hash":"deadbeef","at":"2026-01-01T00:00:00Z","tag":"00"}` + "\n")
	f.Close()

	res, _ := l.Verify(context.Background())
	if res.OK {
		t.Fatal("an anchor with a forged tag must be detected")
	}
	if !strings.Contains(res.Reason, "authentic") {
		t.Fatalf("the reason must be about authenticity; got %q", res.Reason)
	}
}
