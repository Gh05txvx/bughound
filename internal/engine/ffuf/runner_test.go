package ffuf

import (
	"context"
	"strings"
	"testing"
)

func TestRunnerArgs(t *testing.T) {
	r := &Runner{Wordlist: "/wl.txt", RateLimit: 20}
	r.UseProxy("127.0.0.1:9000")
	joined := strings.Join(r.buildArgs("https://demo.test", "/tmp/o.json"), " ")
	for _, want := range []string{
		"-u https://demo.test/FUZZ", "-w /wl.txt", "-of json", "-o /tmp/o.json",
		"-s", "-x http://127.0.0.1:9000", "-rate 20",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("args harus memuat %q; dapat %q", want, joined)
		}
	}
	// FUZZ yang sudah ada tidak digandakan.
	if j := strings.Join(r.buildArgs("https://demo.test/FUZZ", "o"), " "); strings.Contains(j, "FUZZ/FUZZ") {
		t.Errorf("FUZZ eksisting tak boleh digandakan: %q", j)
	}
}

func TestRunnerRequiresWordlist(t *testing.T) {
	r := &Runner{} // tanpa wordlist
	if _, err := r.Scan(context.Background(), "https://demo.test", "p", "run"); err == nil {
		t.Error("run ffuf tanpa wordlist harus gagal (fail-closed)")
	}
}
