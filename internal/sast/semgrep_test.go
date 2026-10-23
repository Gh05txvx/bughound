package sast

import (
	"strings"
	"testing"

	"bughound/internal/finding"
)

func TestSemgrepParse(t *testing.T) {
	fs, err := Parse(strings.NewReader(sampleSemgrepJSON))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 {
		t.Fatalf("harus 2 temuan; dapat %d", len(fs))
	}

	a := fs[0]
	if a.Severity != finding.SeverityHigh {
		t.Errorf("ERROR harus -> high; dapat %s", a.Severity)
	}
	if a.Location.URL != "internal/config/db.go:14" {
		t.Errorf("lokasi harus path:line; dapat %q", a.Location.URL)
	}
	if len(a.CWE) != 1 || a.CWE[0] != "CWE-798" {
		t.Errorf("CWE harus ternormalkan ke CWE-798; dapat %v", a.CWE)
	}
	if a.Evidence == nil || !strings.Contains(a.Evidence.Matched, "dbPassword") {
		t.Errorf("evidence matched kurang: %+v", a.Evidence)
	}
	if a.SourceEngine != "semgrep" {
		t.Errorf("source engine salah: %s", a.SourceEngine)
	}

	b := fs[1]
	if b.Severity != finding.SeverityMedium {
		t.Errorf("WARNING harus -> medium; dapat %s", b.Severity)
	}
	if b.Confidence != finding.ConfidenceMedium {
		t.Errorf("confidence MEDIUM; dapat %s", b.Confidence)
	}
	if len(b.CWE) != 1 || b.CWE[0] != "CWE-338" {
		t.Errorf("CWE-338; dapat %v", b.CWE)
	}
}

func TestSemgrepArgs(t *testing.T) {
	joined := strings.Join((&Runner{}).args("/code/root"), " ")
	for _, want := range []string{"--json", "--config", "auto", "/code/root", "--metrics=off"} {
		if !strings.Contains(joined, want) {
			t.Errorf("args harus memuat %q; dapat %q", want, joined)
		}
	}
	if !strings.Contains(strings.Join((&Runner{Config: "p/golang"}).args("d"), " "), "p/golang") {
		t.Error("Config custom harus dipakai")
	}
}
