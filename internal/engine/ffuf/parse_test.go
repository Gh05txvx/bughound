package ffuf

import (
	"strings"
	"testing"
	"time"

	"bughound/internal/finding"
)

func TestParseSample(t *testing.T) {
	fs, err := Parse(strings.NewReader(string(SampleJSON())), "demo", "run1")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(fs) != 4 {
		t.Fatalf("ingin 4 temuan, dapat %d", len(fs))
	}

	byURL := map[string]*finding.Finding{}
	for _, f := range fs {
		byURL[f.Location.URL] = f
		if f.SourceEngine != "ffuf" || f.Type != "exposed-path" {
			t.Errorf("source/type salah: %s/%s", f.SourceEngine, f.Type)
		}
		if f.Confidence != finding.ConfidenceHigh {
			t.Errorf("confidence ffuf harus high, dapat %s", f.Confidence)
		}
		// Setelah id diberikan store, temuan harus valid.
		f.ID = "x"
		if err := f.Finalize(time.Now()); err != nil {
			t.Errorf("Finalize %s: %v", f.Location.URL, err)
		}
	}

	if got := byURL["https://demo.test/admin"]; got == nil || got.Severity != finding.SeverityLow {
		t.Errorf("/admin (200) harus low")
	}
	if got := byURL["https://demo.test/login"]; got == nil || got.Severity != finding.SeverityInfo {
		t.Errorf("/login (401) harus info")
	}
}

func TestParseEmpty(t *testing.T) {
	fs, err := Parse(strings.NewReader(`{"results":[]}`), "p", "r")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("hasil kosong harus 0 temuan, dapat %d", len(fs))
	}
}

func TestParseInvalid(t *testing.T) {
	if _, err := Parse(strings.NewReader(`{bukan json`), "p", "r"); err == nil {
		t.Fatal("JSON rusak harus error")
	}
}
