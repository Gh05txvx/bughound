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

func TestRunnerBuildArgsSelection(t *testing.T) {
	// Seleksi template: tags & severity → -tags / -severity (koma-join, trim).
	r := &Runner{Tags: []string{"cve", " exposure ", ""}, Severity: []string{"critical", "high"}}
	got := strings.Join(r.buildArgs("https://demo.test"), " ")
	for _, want := range []string{"-tags cve,exposure", "-severity critical,high"} {
		if !strings.Contains(got, want) {
			t.Errorf("args harus memuat %q; dapat: %s", want, got)
		}
	}
}

func TestRunnerBuildArgsNoSelection(t *testing.T) {
	// Seleksi kosong → tak ada flag -tags/-severity (jalankan semua template).
	r := &Runner{Tags: []string{"", "  "}, Severity: nil}
	got := strings.Join(r.buildArgs("https://demo.test"), " ")
	// " -tags " (berspasi awal) membedakan flag seleksi dari "-exclude-tags".
	if strings.Contains(got, " -tags ") || strings.Contains(got, "-severity") {
		t.Errorf("seleksi kosong tak boleh memunculkan flag; dapat: %s", got)
	}
}

// Non-destruktif berlaku juga di plain runner, dengan atau tanpa seleksi template.
func TestRunnerBuildArgsNonDestructive(t *testing.T) {
	for _, r := range []*Runner{{}, {Tags: []string{"cve"}, Severity: []string{"high"}}} {
		got := strings.Join(r.buildArgs("https://demo.test"), " ")
		for _, want := range []string{"-exclude-tags dos,smuggling", "-exclude-id CVE-2021-30118,CVE-2023-46747"} {
			if !strings.Contains(got, want) {
				t.Errorf("buildArgs tak memuat %q; dapat: %s", want, got)
			}
		}
	}
}
