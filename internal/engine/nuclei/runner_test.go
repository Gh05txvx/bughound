package nuclei

import (
	"strings"
	"testing"
)

func TestRunnerBuildArgs(t *testing.T) {
	r := &Runner{RateLimit: 20}
	r.UseProxy("127.0.0.1:9000")
	got := strings.Join(r.buildArgs("https://demo.test"), " ")
	for _, want := range []string{"-jsonl", "-target https://demo.test", "-proxy http://127.0.0.1:9000", "-rate-limit 20"} {
		if !strings.Contains(got, want) {
			t.Errorf("args harus memuat %q; dapat: %s", want, got)
		}
	}
}

func TestRunnerBuildArgsNoProxy(t *testing.T) {
	r := &Runner{}
	got := strings.Join(r.buildArgs("https://demo.test"), " ")
	if strings.Contains(got, "-proxy") {
		t.Errorf("tanpa proxy tak boleh ada flag -proxy; dapat: %s", got)
	}
}
