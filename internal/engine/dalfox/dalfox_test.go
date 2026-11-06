package dalfox

import (
	"context"
	"strings"
	"testing"
)

func TestName(t *testing.T) {
	if (&Runner{}).Name() != "dalfox" {
		t.Fatalf("Name harus dalfox")
	}
}

func TestScanFailSafeNoProxy(t *testing.T) {
	// Tanpa proxy egress, Scan TIDAK boleh mengeksekusi apa pun (tak ada koneksi
	// yang memintas scope guard) — kembalikan nil,nil.
	fs, err := (&Runner{}).Scan(context.Background(), "https://lab.test", "p", "r")
	if err != nil {
		t.Fatalf("fail-safe tak boleh error; dapat %v", err)
	}
	if fs != nil {
		t.Fatalf("tanpa proxy harus nil temuan; dapat %d", len(fs))
	}
}

func TestArgs(t *testing.T) {
	r := &Runner{}
	r.UseProxy("127.0.0.1:9000")
	joined := strings.Join(r.args("https://lab.test/?q=1", "/tmp/out.json"), " ")
	for _, want := range []string{
		"url https://lab.test/?q=1",
		"--format json",
		"--output /tmp/out.json",
		"--proxy http://127.0.0.1:9000",
		"--silence",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("args harus memuat %q; dapat %q", want, joined)
		}
	}
}

func TestStealthReducesWorkersAndAddsDelay(t *testing.T) {
	normal := &Runner{}
	stealth := &Runner{Stealth: true}
	if stealth.workers() >= normal.workers() {
		t.Errorf("stealth harus worker lebih sedikit: %d vs %d", stealth.workers(), normal.workers())
	}
	if stealth.delayMS() <= 0 {
		t.Errorf("stealth harus menambah delay; dapat %d", stealth.delayMS())
	}
	if normal.delayMS() != 0 {
		t.Errorf("tanpa rate/stealth, delay harus 0; dapat %d", normal.delayMS())
	}
	// RateLimit memetakan ke delay.
	if (&Runner{RateLimit: 5}).delayMS() != 200 {
		t.Errorf("RateLimit=5 -> delay 200ms; dapat %d", (&Runner{RateLimit: 5}).delayMS())
	}
}
