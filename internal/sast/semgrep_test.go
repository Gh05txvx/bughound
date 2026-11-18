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
		t.Fatalf("there must be 2 findings; got %d", len(fs))
	}

	a := fs[0]
	if a.Severity != finding.SeverityHigh {
		t.Errorf("ERROR must -> high; got %s", a.Severity)
	}
	if a.Location.URL != "internal/config/db.go:14" {
		t.Errorf("the location must be path:line; got %q", a.Location.URL)
	}
	if len(a.CWE) != 1 || a.CWE[0] != "CWE-798" {
		t.Errorf("CWE must be normalized to CWE-798; got %v", a.CWE)
	}
	if a.Evidence == nil || !strings.Contains(a.Evidence.Matched, "dbPassword") {
		t.Errorf("evidence matched is incomplete: %+v", a.Evidence)
	}
	if a.SourceEngine != "semgrep" {
		t.Errorf("wrong source engine: %s", a.SourceEngine)
	}

	b := fs[1]
	if b.Severity != finding.SeverityMedium {
		t.Errorf("WARNING must -> medium; got %s", b.Severity)
	}
	if b.Confidence != finding.ConfidenceMedium {
		t.Errorf("confidence MEDIUM; got %s", b.Confidence)
	}
	if len(b.CWE) != 1 || b.CWE[0] != "CWE-338" {
		t.Errorf("CWE-338; got %v", b.CWE)
	}
}

func TestSemgrepArgs(t *testing.T) {
	joined := strings.Join((&Runner{}).args("/code/root"), " ")
	// Default `p/default` + metrics OFF (see Runner: `auto` is incompatible with
	// --metrics=off, so it must not be the default).
	for _, want := range []string{"--json", "--config", "p/default", "/code/root", "--metrics=off", "--no-rewrite-rule-ids"} {
		if !strings.Contains(joined, want) {
			t.Errorf("args must contain %q; got %q", want, joined)
		}
	}
	if strings.Contains(joined, " auto ") {
		t.Errorf("the default must not be `auto` (rejected with --metrics=off); got %q", joined)
	}
	if !strings.Contains(strings.Join((&Runner{Config: "p/golang"}).args("d"), " "), "p/golang") {
		t.Error("a custom Config must be used")
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
		t.Fatalf("there must be 2 findings; got %d", len(fs))
	}
	// A registry placeholder -> not evidence, but the finding + location stay.
	if fs[0].Evidence != nil {
		t.Errorf("'requires login' must not become evidence; got %+v", fs[0].Evidence)
	}
	if fs[0].Location.URL != "a.go:3" {
		t.Errorf("the location must stay accurate; got %q", fs[0].Location.URL)
	}
	// Real code lines are kept.
	if fs[1].Evidence == nil || !strings.Contains(fs[1].Evidence.Matched, "realCode") {
		t.Errorf("real code lines must become evidence; got %+v", fs[1].Evidence)
	}
}
