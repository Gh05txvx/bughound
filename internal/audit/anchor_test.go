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
		t.Fatalf("verify harus OK 3 entri + 3 anchor; dapat %+v", res)
	}
	b, _ := os.ReadFile(anchorPath)
	if n := strings.Count(strings.TrimSpace(string(b)), "\n") + 1; n != 3 {
		t.Fatalf("berkas anchor harus 3 baris; dapat %d", n)
	}
}

// BH-F06 inti: rantai internal menerima log kosong (valid), tapi anchor yang
// bertahan mengungkap penghapusan SELURUH store.
func TestAnchorDetectsWholesaleDeletion(t *testing.T) {
	l, _ := openAnchored(t)
	appendN(t, l, 3)

	// Verify rantai saja pada 0 entri akan "OK" — buktikan dulu bahwa itulah
	// celahnya: hapus semua baris di luar aplikasi.
	if _, err := l.db.Exec(`DELETE FROM audit_log`); err != nil {
		t.Fatal(err)
	}
	res, _ := l.Verify(context.Background())
	if res.OK {
		t.Fatal("penghapusan SELURUH log harus terdeteksi lewat anchor")
	}
	if !strings.Contains(res.Reason, "dihapus") && !strings.Contains(res.Reason, "trunkasi") {
		t.Fatalf("alasan harus menyebut penghapusan/trunkasi; dapat %q", res.Reason)
	}
}

func TestAnchorDetectsTruncation(t *testing.T) {
	l, _ := openAnchored(t)
	appendN(t, l, 5)
	// Trunkasi tail: menyisakan prefiks (seq 1..2) yang valid secara rantai.
	if _, err := l.db.Exec(`DELETE FROM audit_log WHERE seq > 2`); err != nil {
		t.Fatal(err)
	}
	res, _ := l.Verify(context.Background())
	if res.OK {
		t.Fatal("trunkasi tail harus terdeteksi lewat anchor (prefiks tetap valid)")
	}
	if res.BrokenAt != 3 {
		t.Fatalf("harus putus pada anchor seq 3; dapat %+v", res)
	}
}

// Rollback: store diganti rantai valid lain (hash berbeda) sementara anchor lama
// bertahan → ketidakcocokan hash head terdeteksi.
func TestAnchorDetectsRollback(t *testing.T) {
	dir := t.TempDir()
	anchorPath := filepath.Join(dir, "a.anchor")
	an := NewFileAnchorer(anchorPath, testKey)
	// Anchor sah (tag benar) untuk seq 1, tapi hash BUKAN milik entri nyata.
	if err := an.WriteAnchor(Anchor{Seq: 1, Hash: "cafebabe", At: time.Unix(0, 0).UTC()}); err != nil {
		t.Fatal(err)
	}
	l, err := OpenSQLiteLog(filepath.Join(dir, "a.db"), testKey, WithAnchorer(an))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	appendN(t, l, 1) // entri nyata seq 1 dengan hash != cafebabe
	res, _ := l.Verify(context.Background())
	if res.OK {
		t.Fatal("ketidakcocokan hash head vs anchor (rollback) harus terdeteksi")
	}
}

func TestAnchorDetectsForgedAnchorFile(t *testing.T) {
	l, anchorPath := openAnchored(t)
	appendN(t, l, 2)
	// Sisipkan anchor dengan tag palsu (seolah berkas anchor diutak-atik).
	f, err := os.OpenFile(anchorPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(`{"seq":2,"hash":"deadbeef","at":"2026-01-01T00:00:00Z","tag":"00"}` + "\n")
	f.Close()

	res, _ := l.Verify(context.Background())
	if res.OK {
		t.Fatal("anchor dengan tag palsu harus terdeteksi")
	}
	if !strings.Contains(res.Reason, "otentik") {
		t.Fatalf("alasan harus soal keotentikan; dapat %q", res.Reason)
	}
}
