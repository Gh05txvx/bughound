package dalfox

import (
	"context"
	"strings"
	"testing"
)

func TestName(t *testing.T) {
	if (&Runner{}).Name() != "dalfox" {
		t.Fatalf("Name must be dalfox")
	}
}

func TestScanFailSafeNoProxy(t *testing.T) {
	// Without the egress proxy, Scan must NOT execute anything (no connection
	// that bypasses the scope guard) — return nil,nil.
	fs, err := (&Runner{}).Scan(context.Background(), "https://lab.test", "p", "r")
	if err != nil {
		t.Fatalf("fail-safe must not error; got %v", err)
	}
	if fs != nil {
		t.Fatalf("without a proxy there must be nil findings; got %d", len(fs))
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
			t.Errorf("args must hold %q; got %q", want, joined)
		}
	}
}

func TestStealthReducesWorkersAndAddsDelay(t *testing.T) {
	normal := &Runner{}
	stealth := &Runner{Stealth: true}
	if stealth.workers() >= normal.workers() {
		t.Errorf("stealth must have fewer workers: %d vs %d", stealth.workers(), normal.workers())
	}
	if stealth.delayMS() <= 0 {
		t.Errorf("stealth must add delay; got %d", stealth.delayMS())
	}
	if normal.delayMS() != 0 {
		t.Errorf("without rate/stealth, delay must be 0; got %d", normal.delayMS())
	}
	// RateLimit maps to delay.
	if (&Runner{RateLimit: 5}).delayMS() != 200 {
		t.Errorf("RateLimit=5 -> delay 200ms; got %d", (&Runner{RateLimit: 5}).delayMS())
	}
}
