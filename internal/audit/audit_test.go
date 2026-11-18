package audit

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
)

var testKey = []byte("audit-hmac-test-key")

type logFactory struct {
	name string
	open func(t *testing.T, key []byte) Log
}

func factories() []logFactory {
	return []logFactory{
		{"mem", func(t *testing.T, key []byte) Log { return NewMemLog(key) }},
		{"sqlite", func(t *testing.T, key []byte) Log {
			l, err := OpenSQLiteLog(filepath.Join(t.TempDir(), "a.db"), key)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { l.Close() })
			return l
		}},
	}
}

func appendN(t *testing.T, l Log, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		_, err := l.Append(context.Background(), Event{
			Kind: "scope.decision", Program: "demo", Target: fmt.Sprintf("t%d.demo.test", i),
			Allowed: i%2 == 0, Reason: "not-in-scope", Layer: "input",
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestAppendAndVerifyOK(t *testing.T) {
	for _, f := range factories() {
		t.Run(f.name, func(t *testing.T) {
			l := f.open(t, testKey)
			appendN(t, l, 3)
			res, err := l.Verify(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if !res.OK || res.Count != 3 {
				t.Fatalf("verify must be OK with 3 entries; got %+v", res)
			}
		})
	}
}

func TestListNewestFirstAndFilter(t *testing.T) {
	for _, f := range factories() {
		t.Run(f.name, func(t *testing.T) {
			l := f.open(t, testKey)
			ctx := context.Background()
			l.Append(ctx, Event{Kind: "scope.decision", Program: "a", Target: "first"})
			l.Append(ctx, Event{Kind: "run.start", Program: "b", Target: "second"})
			l.Append(ctx, Event{Kind: "scope.decision", Program: "a", Target: "third"})

			all, _ := l.List(ctx, Filter{})
			if len(all) != 3 || all[0].Target != "third" {
				t.Fatalf("List must be newest first; got %d, [0]=%q", len(all), all[0].Target)
			}
			if a, _ := l.List(ctx, Filter{Program: "a"}); len(a) != 2 {
				t.Errorf("filter program=a must return 2; got %d", len(a))
			}
			if k, _ := l.List(ctx, Filter{Kind: "run.start"}); len(k) != 1 {
				t.Errorf("the kind filter must return 1; got %d", len(k))
			}
			if lim, _ := l.List(ctx, Filter{Limit: 1}); len(lim) != 1 || lim[0].Target != "third" {
				t.Errorf("limit 1 must return the newest entry")
			}
		})
	}
}

func TestMemTamperDetected(t *testing.T) {
	l := NewMemLog(testKey)
	appendN(t, l, 3)
	l.events[1].Message = "CHANGED" // change the entry directly
	res, _ := l.Verify(context.Background())
	if res.OK || res.BrokenAt != 2 {
		t.Fatalf("the changed entry must be detected at seq 2; got %+v", res)
	}
}

func TestMemDeletionDetected(t *testing.T) {
	l := NewMemLog(testKey)
	appendN(t, l, 3)
	l.events = []Event{l.events[0], l.events[2]} // delete the middle entry
	res, _ := l.Verify(context.Background())
	if res.OK {
		t.Fatal("the deleted entry must be detected")
	}
}

func TestSQLiteTamperDetected(t *testing.T) {
	l, err := OpenSQLiteLog(filepath.Join(t.TempDir(), "a.db"), testKey)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	appendN(t, l, 3)
	if _, err := l.db.Exec(`UPDATE audit_log SET message=? WHERE seq=2`, "CHANGED"); err != nil {
		t.Fatal(err)
	}
	res, _ := l.Verify(context.Background())
	if res.OK || res.BrokenAt != 2 {
		t.Fatalf("the changed row must be detected at seq 2; got %+v", res)
	}
}

func TestSQLiteDeletionDetected(t *testing.T) {
	l, err := OpenSQLiteLog(filepath.Join(t.TempDir(), "a.db"), testKey)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	appendN(t, l, 3)
	if _, err := l.db.Exec(`DELETE FROM audit_log WHERE seq=2`); err != nil {
		t.Fatal(err)
	}
	res, _ := l.Verify(context.Background())
	if res.OK {
		t.Fatal("the deleted row must be detected (seq gap / broken chain)")
	}
}

func TestWrongKeyFailsVerify(t *testing.T) {
	l := NewMemLog(testKey)
	appendN(t, l, 2)
	// Verifying with a different key must fail (the chain cannot be recomputed without the key).
	l.key = []byte("wrong-key")
	res, _ := l.Verify(context.Background())
	if res.OK {
		t.Fatal("verify with the wrong key must fail")
	}
}
