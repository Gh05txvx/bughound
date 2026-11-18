package zap

import (
	"bytes"
	"strings"
	"testing"

	"bughound/internal/finding"
)

func TestParseSample(t *testing.T) {
	fs, err := Parse(bytes.NewReader(sampleJSON), "demo", "run1")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 {
		t.Fatalf("must be 2 findings (1 instance per alert); got %d", len(fs))
	}

	a := fs[0]
	if a.Type != "sql-injection" {
		t.Errorf("type must be the slug 'sql-injection'; got %q", a.Type)
	}
	if a.Severity != finding.SeverityHigh {
		t.Errorf("riskcode 3 must -> high; got %s", a.Severity)
	}
	if a.Confidence != finding.ConfidenceMedium {
		t.Errorf("confidence 2 must -> medium; got %s", a.Confidence)
	}
	if len(a.CWE) != 1 || a.CWE[0] != "CWE-89" {
		t.Errorf("CWE must be CWE-89; got %v", a.CWE)
	}
	if a.Location.URL != "https://demo.test/item?id=1" || a.Location.Parameter != "id" || a.Location.Method != "GET" {
		t.Errorf("wrong location/param/method: %+v", a.Location)
	}
	if a.Evidence == nil || !strings.Contains(a.Evidence.Matched, "SQL syntax") {
		t.Errorf("evidence missing: %+v", a.Evidence)
	}
	if a.SourceEngine != "zap" || a.Target != "https://demo.test" {
		t.Errorf("wrong source/target: %s/%s", a.SourceEngine, a.Target)
	}
	if strings.Contains(a.Description, "<p>") {
		t.Errorf("the description must be free of HTML tags; got %q", a.Description)
	}

	b := fs[1]
	if b.Type != "cross-site-scripting-reflected" {
		t.Errorf("wrong XSS slug: %q", b.Type)
	}
	if b.Severity != finding.SeverityMedium {
		t.Errorf("riskcode 2 must -> medium; got %s", b.Severity)
	}
	if b.Confidence != finding.ConfidenceHigh {
		t.Errorf("confidence 3 must -> high; got %s", b.Confidence)
	}
	if len(b.CWE) != 1 || b.CWE[0] != "CWE-79" {
		t.Errorf("CWE must be CWE-79; got %v", b.CWE)
	}
}

func TestRunnerArgs(t *testing.T) {
	r := &Runner{}
	plain := strings.Join(r.buildPlanArgs("/tmp/plan.yaml", "/tmp/zaprun"), " ")
	// -dir: ZAP home per run (not the shared ~/.ZAP) — a regression of auth session leaking
	// across runs/programs via config.xml (live 2026-11-16).
	for _, want := range []string{"-cmd", "-dir /tmp/zaprun", "-autorun /tmp/plan.yaml"} {
		if !strings.Contains(plain, want) {
			t.Errorf("args must hold %q; got %q", want, plain)
		}
	}
	if strings.Contains(plain, "httpProxy") {
		t.Error("without a proxy there must be no proxy config")
	}

	r.UseProxy("127.0.0.1:9000")
	withProxy := strings.Join(r.buildPlanArgs("/tmp/plan.yaml", "/tmp/zaprun"), " ")
	for _, want := range []string{
		"network.connection.httpProxy.host=127.0.0.1",
		"network.connection.httpProxy.port=9000",
		"network.connection.httpProxy.enabled=true",
	} {
		if !strings.Contains(withProxy, want) {
			t.Errorf("the proxy args must hold %q; got %q", want, withProxy)
		}
	}
}

// throttleArgs: without RateLimit there is no gap; with RateLimit=20 → 1 thread per
// host + a 1000/20=50ms gap (affects the active scan in full mode).
func TestRunnerThrottle(t *testing.T) {
	if plain := strings.Join((&Runner{}).buildPlanArgs("/tmp/plan.yaml", "/tmp/zaprun"), " "); strings.Contains(plain, "scanner.delayInMs") {
		t.Errorf("without RateLimit there must be no throttle; got %q", plain)
	}
	got := strings.Join((&Runner{RateLimit: 20}).buildPlanArgs("/tmp/plan.yaml", "/tmp/zaprun"), " ")
	for _, want := range []string{"scanner.threadPerHost=1", "scanner.delayInMs=50"} {
		if !strings.Contains(got, want) {
			t.Errorf("the throttle must hold %q; got %q", want, got)
		}
	}
}

func TestRunnerModes(t *testing.T) {
	if (&Runner{}).mode() != "quick" || (&Runner{}).active() {
		t.Error("the default mode must be quick & PASSIVE (active=false)")
	}
	if (&Runner{Mode: "baseline"}).active() {
		t.Error("baseline must be passive (active=false)")
	}
	full := &Runner{Mode: "full"}
	if full.mode() != "full" || !full.active() {
		t.Error("Mode=full must be read & active")
	}
	full.UseProxy("127.0.0.1:9000")
	args := strings.Join(full.buildPlanArgs("/tmp/plan.yaml", "/tmp/zaprun"), " ")
	for _, want := range []string{"-autorun /tmp/plan.yaml", "network.connection.httpProxy.host=127.0.0.1"} {
		if !strings.Contains(args, want) {
			t.Errorf("args must hold %q; got %q", want, args)
		}
	}
}

// Option (a) security guarantee: a PASSIVE-mode plan (quick/baseline) NEVER holds
// activeScan; a FULL plan holds activeScan, not passiveScan-wait. Both still have
// spider + JSON report + duration limits.
func TestPlanYAMLActiveVsPassive(t *testing.T) {
	common := []string{"spider", "https://demo.test", "traditional-json", `reportFile: "report.json"`, "maxDuration: 3"}

	passive := planYAML("https://demo.test", "/out", "report.json", false, nil)
	for _, want := range append([]string{"passiveScan-wait", "maxDuration: 5"}, common...) {
		if !strings.Contains(passive, want) {
			t.Errorf("the passive plan must hold %q", want)
		}
	}
	if strings.Contains(passive, "activeScan") {
		t.Errorf("the passive plan must NOT hold activeScan:\n%s", passive)
	}

	active := planYAML("https://demo.test", "/out", "report.json", true, nil)
	for _, want := range append([]string{"activeScan", "maxScanDurationInMins: 10", "maxRuleDurationInMins: 2"}, common...) {
		if !strings.Contains(active, want) {
			t.Errorf("the active plan must hold %q", want)
		}
	}
	if strings.Contains(active, "passiveScan-wait") {
		t.Errorf("the active plan does not need passiveScan-wait:\n%s", active)
	}
}
