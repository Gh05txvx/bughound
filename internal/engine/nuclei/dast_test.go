package nuclei

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestDASTScanNoProxyNoConnect(t *testing.T) {
	// Fail-safe keamanan: tanpa proxy egress, Scan tak boleh membuat koneksi apa
	// pun (return nil,nil). Juga membuat Scan teruji tanpa binary nuclei/katana.
	r := &DASTRunner{}
	fs, err := r.Scan(context.Background(), "http://t.test/", "p", "run1")
	if err != nil || fs != nil {
		t.Fatalf("tanpa proxy harus nil,nil; dapat %v,%v", fs, err)
	}
}

func TestSameHostURLs(t *testing.T) {
	in := []string{
		"http://t.test/a?x=1",
		"http://t.test/a?x=1", // dup
		"http://t.test/b",
		"https://evil.test/c", // host beda -> buang
		"  http://t.test/d  ", // spasi
		"::::not a url",       // tak terurai -> buang
	}
	got := sameHostURLs("http://t.test/", in)
	want := map[string]bool{"http://t.test/a?x=1": true, "http://t.test/b": true, "http://t.test/d": true}
	if len(got) != len(want) {
		t.Fatalf("sameHostURLs = %v; mau %d unik same-host", got, len(want))
	}
	for _, u := range got {
		if !want[u] {
			t.Errorf("URL tak terduga (cross-host lolos?): %q", u)
		}
	}
}

func TestPrioritizeURLs(t *testing.T) {
	in := []string{"http://t/x", "http://t/y?q=1", "http://t/z", "http://t/w?a=2"}
	got := prioritizeURLs(in, 10)
	// URL berparameter harus lebih dulu.
	if !strings.Contains(got[0], "?") || !strings.Contains(got[1], "?") {
		t.Errorf("URL berparameter harus diprioritaskan; dapat %v", got)
	}
	// Cap dihormati.
	if capped := prioritizeURLs(in, 2); len(capped) != 2 {
		t.Errorf("cap tak dihormati; dapat %d", len(capped))
	}
}

func TestNucleiArgs(t *testing.T) {
	r := &DASTRunner{RateLimit: 25, proxyAddr: "127.0.0.1:9000"}
	a := strings.Join(r.nucleiArgs("/tmp/list.txt"), " ")
	for _, want := range []string{"-dast", "-jsonl", "-list /tmp/list.txt", "-proxy http://127.0.0.1:9000", "-fuzz-aggression low", "-rate-limit 25"} {
		if !strings.Contains(a, want) {
			t.Errorf("nucleiArgs tak memuat %q; got: %s", want, a)
		}
	}
	// Aggression kustom dihormati.
	r2 := &DASTRunner{Aggression: "medium", proxyAddr: "x:1"}
	if !strings.Contains(strings.Join(r2.nucleiArgs("l"), " "), "-fuzz-aggression medium") {
		t.Error("Aggression kustom tak diteruskan")
	}
}

func TestKatanaArgs(t *testing.T) {
	r := &DASTRunner{RateLimit: 12, proxyAddr: "127.0.0.1:9000"}
	a := strings.Join(r.katanaArgs("http://t.test/"), " ")
	for _, want := range []string{"-u http://t.test/", "-proxy http://127.0.0.1:9000", "-jc", "-rate-limit 12"} {
		if !strings.Contains(a, want) {
			t.Errorf("katanaArgs tak memuat %q; got: %s", want, a)
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
		t.Fatalf("baca list: %v", err)
	}
	got := strings.TrimSpace(string(b))
	if got != strings.Join(urls, "\n") {
		t.Errorf("isi list = %q", got)
	}
	cleanup()
	if _, err := os.Stat(name); !os.IsNotExist(err) {
		t.Error("cleanup harus menghapus berkas list")
	}
}
