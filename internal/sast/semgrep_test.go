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
	// Default `p/default` + metrics OFF (lihat Runner: `auto` tak kompatibel
	// dengan --metrics=off, jadi tak boleh jadi default).
	for _, want := range []string{"--json", "--config", "p/default", "/code/root", "--metrics=off", "--no-rewrite-rule-ids"} {
		if !strings.Contains(joined, want) {
			t.Errorf("args harus memuat %q; dapat %q", want, joined)
		}
	}
	if strings.Contains(joined, " auto ") {
		t.Errorf("default tak boleh `auto` (tolak saat --metrics=off); dapat %q", joined)
	}
	if !strings.Contains(strings.Join((&Runner{Config: "p/golang"}).args("d"), " "), "p/golang") {
		t.Error("Config custom harus dipakai")
	}
}

func TestSemgrepParse_DropsRequiresLoginPlaceholder(t *testing.T) {
	const js = `{"results":[
	  {"check_id":"rules.a","path":"a.go","start":{"line":3},
	   "extra":{"message":"m1","severity":"ERROR","lines":"requires login","metadata":{}}},
	  {"check_id":"rules.b","path":"b.go","start":{"line":5},
	   "extra":{"message":"m2","severity":"WARNING","lines":"  realCode := 1","metadata":{}}}
	]}`
	fs, err := Parse(strings.NewReader(js))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 {
		t.Fatalf("harus 2 temuan; dapat %d", len(fs))
	}
	// Placeholder registry -> tak jadi evidence, tapi temuan + lokasi tetap ada.
	if fs[0].Evidence != nil {
		t.Errorf("'requires login' tak boleh jadi evidence; dapat %+v", fs[0].Evidence)
	}
	if fs[0].Location.URL != "a.go:3" {
		t.Errorf("lokasi harus tetap akurat; dapat %q", fs[0].Location.URL)
	}
	// Baris kode sungguhan tetap dipertahankan.
	if fs[1].Evidence == nil || !strings.Contains(fs[1].Evidence.Matched, "realCode") {
		t.Errorf("baris kode asli harus jadi evidence; dapat %+v", fs[1].Evidence)
	}
}
