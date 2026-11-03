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
			t.Errorf("args harus memuat %q; dapat %q", want, joined)
		}
	}
	// FUZZ yang sudah ada tidak digandakan.
	if j := strings.Join(r.buildArgs("https://demo.test/FUZZ", "o", "wl"), " "); strings.Contains(j, "FUZZ/FUZZ") {
		t.Errorf("FUZZ eksisting tak boleh digandakan: %q", j)
	}
}

func TestDefaultWordlistUsedWhenEmpty(t *testing.T) {
	if len(defaultWordlist) == 0 {
		t.Fatal("wordlist bawaan tak boleh kosong")
	}
	for _, want := range []string{"admin", ".env", ".git/config", "robots.txt", "ftp", "rest/products/search"} {
		if !strings.Contains(string(defaultWordlist), want) {
			t.Errorf("wordlist bawaan harus memuat %q", want)
		}
	}

	// Tanpa Wordlist: resolve ke berkas sementara berisi wordlist bawaan.
	r := &Runner{}
	path, cleanup, err := r.resolveWordlist()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("baca wordlist bawaan: %v", err)
	}
	if !strings.Contains(string(data), "admin") {
		t.Error("berkas wordlist sementara harus berisi entri bawaan")
	}

	// Dengan Wordlist: dipakai apa adanya (tanpa berkas sementara).
	r2 := &Runner{Wordlist: "/custom/wl.txt"}
	p2, _, err := r2.resolveWordlist()
	if err != nil || p2 != "/custom/wl.txt" {
		t.Errorf("wordlist kustom harus dipakai apa adanya; dapat %q (%v)", p2, err)
	}
}

// TestDefaultWordlistSane menjaga integritas wordlist bawaan: ffuf memprobe SETIAP
// baris sebagai path, jadi baris kosong, komentar (#...), spasi tepi, atau entri
// duplikat akan memboroskan request atau memprobe path sampah.
func TestDefaultWordlistSane(t *testing.T) {
	seen := map[string]bool{}
	for i, ln := range strings.Split(strings.TrimRight(string(defaultWordlist), "\n"), "\n") {
		n := i + 1
		if strings.TrimSpace(ln) == "" {
			t.Errorf("baris %d kosong", n)
			continue
		}
		if strings.HasPrefix(ln, "#") {
			t.Errorf("baris %d komentar (ffuf akan memprobe-nya sbg path): %q", n, ln)
		}
		if ln != strings.TrimSpace(ln) {
			t.Errorf("baris %d ada spasi tepi: %q", n, ln)
		}
		if seen[ln] {
			t.Errorf("baris %d duplikat: %q", n, ln)
		}
		seen[ln] = true
	}
}
