package nuclei

import "testing"

func hasHeaderArg(args []string, hdr string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-H" && args[i+1] == hdr {
			return true
		}
	}
	return false
}

func TestRunnerBuildArgsAuthHeaders(t *testing.T) {
	hdr := "Cookie: session=abc"
	r := &Runner{}
	if hasHeaderArg(r.buildArgs("http://t"), hdr) {
		t.Error("tanpa UseAuthHeaders tak boleh ada -H")
	}
	r.UseAuthHeaders([]string{hdr, "", "  "}) // elemen kosong diabaikan
	a := r.buildArgs("http://t")
	if !hasHeaderArg(a, hdr) {
		t.Errorf("buildArgs harus memuat -H %q: %v", hdr, a)
	}
	// hanya satu -H (elemen kosong tak ikut)
	n := 0
	for _, x := range a {
		if x == "-H" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("mau 1 -H, dapat %d: %v", n, a)
	}
}

func TestDASTRunnerAuthHeaders(t *testing.T) {
	hdr := "Authorization: Bearer xyz"
	r := &DASTRunner{proxyAddr: "127.0.0.1:1"}
	r.UseAuthHeaders([]string{hdr})
	if !hasHeaderArg(r.katanaArgs("http://t"), hdr) {
		t.Error("katanaArgs (crawl) harus memuat -H auth")
	}
	if !hasHeaderArg(r.nucleiArgsMode("f", ""), hdr) {
		t.Error("nucleiArgsMode (fuzz) harus memuat -H auth")
	}
}
