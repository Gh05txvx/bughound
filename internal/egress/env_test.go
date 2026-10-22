package egress

import (
	"strings"
	"testing"
)

func TestProxyEnv(t *testing.T) {
	got := ProxyEnv([]string{"PATH=/bin", "HTTP_PROXY=http://lama", "FOO=bar"}, "http://127.0.0.1:9000")
	j := strings.Join(got, "\n")

	if !strings.Contains(j, "PATH=/bin") || !strings.Contains(j, "FOO=bar") {
		t.Error("env non-proxy harus dipertahankan")
	}
	if strings.Contains(j, "http://lama") {
		t.Error("HTTP_PROXY lama harus dibuang")
	}
	for _, want := range []string{"HTTP_PROXY=http://127.0.0.1:9000", "HTTPS_PROXY=http://127.0.0.1:9000", "ALL_PROXY=http://127.0.0.1:9000", "NO_PROXY="} {
		if !strings.Contains(j, want) {
			t.Errorf("env harus memuat %q", want)
		}
	}
}
