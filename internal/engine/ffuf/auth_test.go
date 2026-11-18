package ffuf

import "testing"

func hasHeaderArg(args []string, hdr string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-H" && args[i+1] == hdr {
			return true
		}
	}
	return false
}

func TestBuildArgsAuthHeaders(t *testing.T) {
	hdr := "Cookie: session=abc"
	r := &Runner{}
	if hasHeaderArg(r.buildArgs("http://t", "out.json", "wl.txt"), hdr) {
		t.Error("without UseAuthHeaders there must be no -H")
	}
	r.UseAuthHeaders([]string{hdr})
	if !hasHeaderArg(r.buildArgs("http://t", "out.json", "wl.txt"), hdr) {
		t.Errorf("buildArgs must contain -H %q", hdr)
	}
}
