package ffuf

import (
	"os"
	"strings"
	"testing"
)

func TestRunnerArgs(t *testing.T) {
	r := &Runner{RateLimit: 20}
	r.UseProxy("127.0.0.1:9000")
	joined := strings.Join(r.buildArgs("https://demo.test", "/tmp/o.json", "/wl.txt"), " ")
	for _, want := range []string{
		"-u https://demo.test/FUZZ", "-w /wl.txt", "-of json", "-o /tmp/o.json",
		"-s", "-ac", "-x http://127.0.0.1:9000", "-rate 20",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("args must contain %q; got %q", want, joined)
		}
	}
	// An existing FUZZ is not duplicated.
	if j := strings.Join(r.buildArgs("https://demo.test/FUZZ", "o", "wl"), " "); strings.Contains(j, "FUZZ/FUZZ") {
		t.Errorf("an existing FUZZ must not be duplicated: %q", j)
	}
}

func TestDefaultWordlistUsedWhenEmpty(t *testing.T) {
	if len(defaultWordlist) == 0 {
		t.Fatal("the built-in wordlist must not be empty")
	}
	for _, want := range []string{"admin", ".env", ".git/config", "robots.txt", "ftp", "rest/products/search"} {
		if !strings.Contains(string(defaultWordlist), want) {
			t.Errorf("the built-in wordlist must contain %q", want)
		}
	}

	// Without a Wordlist: resolve to a temp file holding the built-in wordlist.
	r := &Runner{}
	path, cleanup, err := r.resolveWordlist()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read built-in wordlist: %v", err)
	}
	if !strings.Contains(string(data), "admin") {
		t.Error("the temp wordlist file must hold the built-in entries")
	}

	// With a Wordlist: used as-is (no temp file).
	r2 := &Runner{Wordlist: "/custom/wl.txt"}
	p2, _, err := r2.resolveWordlist()
	if err != nil || p2 != "/custom/wl.txt" {
		t.Errorf("a custom wordlist must be used as-is; got %q (%v)", p2, err)
	}
}

// TestDefaultWordlistSane guards the built-in wordlist's integrity: ffuf probes
// EVERY line as a path, so a blank line, a comment (#...), edge whitespace, or a
// duplicate entry would waste a request or probe a junk path.
func TestDefaultWordlistSane(t *testing.T) {
	seen := map[string]bool{}
	for i, ln := range strings.Split(strings.TrimRight(string(defaultWordlist), "\n"), "\n") {
		n := i + 1
		if strings.TrimSpace(ln) == "" {
			t.Errorf("line %d is empty", n)
			continue
		}
		if strings.HasPrefix(ln, "#") {
			t.Errorf("line %d is a comment (ffuf would probe it as a path): %q", n, ln)
		}
		if ln != strings.TrimSpace(ln) {
			t.Errorf("line %d has edge whitespace: %q", n, ln)
		}
		if seen[ln] {
			t.Errorf("line %d is a duplicate: %q", n, ln)
		}
		seen[ln] = true
	}
}
