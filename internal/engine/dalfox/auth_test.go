package dalfox

import "testing"

func hasHeaderArg(args []string, hdr string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-H" && args[i+1] == hdr {
			return true
		}
	}
	return false
}

func TestArgsAuthHeaders(t *testing.T) {
	hdr := "Cookie: session=abc"
	r := &Runner{proxyAddr: "127.0.0.1:1"}
	if hasHeaderArg(r.args("http://t", "out.json"), hdr) {
		t.Error("tanpa UseAuthHeaders tak boleh ada -H")
	}
	r.UseAuthHeaders([]string{hdr})
	if !hasHeaderArg(r.args("http://t", "out.json"), hdr) {
		t.Errorf("args harus memuat -H %q", hdr)
	}
}
