package nuclei

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestDASTScanNoProxyNoConnect(t *testing.T) {
	// Security fail-safe: without an egress proxy, Scan must make no connection at all
	// (return nil,nil). It also lets Scan be tested without the nuclei/katana binary.
	r := &DASTRunner{}
	fs, err := r.Scan(context.Background(), "http://t.test/", "p", "run1")
	if err != nil || fs != nil {
		t.Fatalf("without a proxy must be nil,nil; got %v,%v", fs, err)
	}
}

func TestSameHostURLs(t *testing.T) {
	in := []string{
		"http://t.test/a?x=1",
		"http://t.test/a?x=1", // dup
		"http://t.test/b",
		"https://evil.test/c", // different host -> drop
		"  http://t.test/d  ", // whitespace
		"::::not a url",       // does not parse -> drop
	}
	got := sameHostURLs("http://t.test/", in)
	want := map[string]bool{"http://t.test/a?x=1": true, "http://t.test/b": true, "http://t.test/d": true}
	if len(got) != len(want) {
		t.Fatalf("sameHostURLs = %v; want %d unique same-host", got, len(want))
	}
	for _, u := range got {
		if !want[u] {
			t.Errorf("unexpected URL (cross-host leaked?): %q", u)
		}
	}
}

func TestPrioritizeURLs(t *testing.T) {
	in := []string{"http://t/x", "http://t/y?q=1", "http://t/z", "http://t/w?a=2"}
	got := prioritizeURLs(in, 10)
	// Parameterized URLs must come first.
	if !strings.Contains(got[0], "?") || !strings.Contains(got[1], "?") {
		t.Errorf("parameterized URLs must be prioritized; got %v", got)
	}
	// The cap is honored.
	if capped := prioritizeURLs(in, 2); len(capped) != 2 {
		t.Errorf("the cap was not honored; got %d", len(capped))
	}
}

func TestNucleiArgs(t *testing.T) {
	r := &DASTRunner{RateLimit: 25, proxyAddr: "127.0.0.1:9000"}
	a := strings.Join(r.nucleiArgs("/tmp/list.txt"), " ")
	for _, want := range []string{"-dast", "-jsonl", "-list /tmp/list.txt", "-proxy http://127.0.0.1:9000", "-fuzz-aggression low", "-rate-limit 25"} {
		if !strings.Contains(a, want) {
			t.Errorf("nucleiArgs does not contain %q; got: %s", want, a)
		}
	}
	// A custom aggression is honored.
	r2 := &DASTRunner{Aggression: "medium", proxyAddr: "x:1"}
	if !strings.Contains(strings.Join(r2.nucleiArgs("l"), " "), "-fuzz-aggression medium") {
		t.Error("the custom aggression was not passed through")
	}
}

func TestKatanaArgs(t *testing.T) {
	r := &DASTRunner{RateLimit: 12, proxyAddr: "127.0.0.1:9000"}
	a := strings.Join(r.katanaArgs("http://t.test/"), " ")
	for _, want := range []string{"-u http://t.test/", "-proxy http://127.0.0.1:9000", "-jc", "-rate-limit 12"} {
		if !strings.Contains(a, want) {
			t.Errorf("katanaArgs does not contain %q; got: %s", want, a)
		}
	}
}

func TestWriteList(t *testing.T) {
	urls := []string{"http://t.test/a", "http://t.test/b?x=1"}
	name, cleanup, err := writeList(urls)
	if err != nil {
		t.Fatalf("writeList: %v", err)
	}
	defer cleanup()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read list: %v", err)
	}
	got := strings.TrimSpace(string(b))
	if got != strings.Join(urls, "\n") {
		t.Errorf("list contents = %q", got)
	}
	cleanup()
	if _, err := os.Stat(name); !os.IsNotExist(err) {
		t.Error("cleanup must remove the list file")
	}
}
