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
				t.Fatalf("verify harus OK dengan 3 entri; dapat %+v", res)
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
				t.Fatalf("List harus terbaru dulu; dapat %d, [0]=%q", len(all), all[0].Target)
			}
			if a, _ := l.List(ctx, Filter{Program: "a"}); len(a) != 2 {
				t.Errorf("filter program=a harus 2; dapat %d", len(a))
			}
			if k, _ := l.List(ctx, Filter{Kind: "run.start"}); len(k) != 1 {
				t.Errorf("filter kind harus 1; dapat %d", len(k))
			}
			if lim, _ := l.List(ctx, Filter{Limit: 1}); len(lim) != 1 || lim[0].Target != "third" {
				t.Errorf("limit 1 harus entri terbaru")
			}
		})
	}
}

func TestMemTamperDetected(t *testing.T) {
	l := NewMemLog(testKey)
	appendN(t, l, 3)
	l.events[1].Message = "DIUBAH" // ubah entri langsung
	res, _ := l.Verify(context.Background())
	if res.OK || res.BrokenAt != 2 {
		t.Fatalf("perubahan entri harus terdeteksi di seq 2; dapat %+v", res)
	}
}

func TestMemDeletionDetected(t *testing.T) {
	l := NewMemLog(testKey)
	appendN(t, l, 3)
	l.events = []Event{l.events[0], l.events[2]} // hapus entri tengah
	res, _ := l.Verify(context.Background())
	if res.OK {
		t.Fatal("penghapusan entri harus terdeteksi")
	}
}

func TestSQLiteTamperDetected(t *testing.T) {
	l, err := OpenSQLiteLog(filepath.Join(t.TempDir(), "a.db"), testKey)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	appendN(t, l, 3)
	if _, err := l.db.Exec(`UPDATE audit_log SET message=? WHERE seq=2`, "DIUBAH"); err != nil {
		t.Fatal(err)
	}
	res, _ := l.Verify(context.Background())
	if res.OK || res.BrokenAt != 2 {
		t.Fatalf("perubahan baris harus terdeteksi di seq 2; dapat %+v", res)
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
		t.Fatal("penghapusan baris harus terdeteksi (gap seq / rantai putus)")
	}
}

func TestWrongKeyFailsVerify(t *testing.T) {
	l := NewMemLog(testKey)
	appendN(t, l, 2)
	// Verifikasi dengan kunci berbeda harus gagal (rantai tak bisa dihitung ulang tanpa kunci).
	l.key = []byte("kunci-salah")
	res, _ := l.Verify(context.Background())
	if res.OK {
		t.Fatal("verify dengan kunci salah harus gagal")
	}
}
