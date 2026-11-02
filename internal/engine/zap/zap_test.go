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
		t.Fatalf("harus 2 temuan (1 instance per alert); dapat %d", len(fs))
	}

	a := fs[0]
	if a.Type != "sql-injection" {
		t.Errorf("type harus slug 'sql-injection'; dapat %q", a.Type)
	}
	if a.Severity != finding.SeverityHigh {
		t.Errorf("riskcode 3 harus -> high; dapat %s", a.Severity)
	}
	if a.Confidence != finding.ConfidenceMedium {
		t.Errorf("confidence 2 harus -> medium; dapat %s", a.Confidence)
	}
	if len(a.CWE) != 1 || a.CWE[0] != "CWE-89" {
		t.Errorf("CWE harus CWE-89; dapat %v", a.CWE)
	}
	if a.Location.URL != "https://demo.test/item?id=1" || a.Location.Parameter != "id" || a.Location.Method != "GET" {
		t.Errorf("lokasi/param/method salah: %+v", a.Location)
	}
	if a.Evidence == nil || !strings.Contains(a.Evidence.Matched, "SQL syntax") {
		t.Errorf("evidence kurang: %+v", a.Evidence)
	}
	if a.SourceEngine != "zap" || a.Target != "https://demo.test" {
		t.Errorf("source/target salah: %s/%s", a.SourceEngine, a.Target)
	}
	if strings.Contains(a.Description, "<p>") {
		t.Errorf("deskripsi harus bebas tag HTML; dapat %q", a.Description)
	}

	b := fs[1]
	if b.Type != "cross-site-scripting-reflected" {
		t.Errorf("slug XSS salah: %q", b.Type)
	}
	if b.Severity != finding.SeverityMedium {
		t.Errorf("riskcode 2 harus -> medium; dapat %s", b.Severity)
	}
	if b.Confidence != finding.ConfidenceHigh {
		t.Errorf("confidence 3 harus -> high; dapat %s", b.Confidence)
	}
	if len(b.CWE) != 1 || b.CWE[0] != "CWE-79" {
		t.Errorf("CWE harus CWE-79; dapat %v", b.CWE)
	}
}

func TestRunnerArgs(t *testing.T) {
	r := &Runner{}
	plain := strings.Join(r.buildArgs("https://demo.test", "/tmp/o.json"), " ")
	for _, want := range []string{"-cmd", "-quickurl https://demo.test", "-quickout /tmp/o.json"} {
		if !strings.Contains(plain, want) {
			t.Errorf("args harus memuat %q; dapat %q", want, plain)
		}
	}
	if strings.Contains(plain, "httpProxy") {
		t.Error("tanpa proxy tak boleh ada config proxy")
	}

	r.UseProxy("127.0.0.1:9000")
	withProxy := strings.Join(r.buildArgs("https://demo.test", "o"), " ")
	for _, want := range []string{
		"network.connection.httpProxy.host=127.0.0.1",
		"network.connection.httpProxy.port=9000",
		"network.connection.httpProxy.enabled=true",
	} {
		if !strings.Contains(withProxy, want) {
			t.Errorf("args proxy harus memuat %q; dapat %q", want, withProxy)
		}
	}
}

// throttleArgs: tanpa RateLimit tak ada jeda; dengan RateLimit=20 → 1 thread per
// host + jeda 1000/20=50ms, berlaku di mode quick maupun full (active scan).
func TestRunnerThrottle(t *testing.T) {
	if plain := strings.Join((&Runner{}).buildArgs("https://demo.test", "/tmp/o.json"), " "); strings.Contains(plain, "scanner.delayInMs") {
		t.Errorf("tanpa RateLimit tak boleh ada throttle; dapat %q", plain)
	}
	r := &Runner{RateLimit: 20}
	for _, got := range []string{
		strings.Join(r.buildArgs("https://demo.test", "/tmp/o.json"), " "),
		strings.Join(r.buildFullArgs("/tmp/plan.yaml"), " "),
	} {
		for _, want := range []string{"scanner.threadPerHost=1", "scanner.delayInMs=50"} {
			if !strings.Contains(got, want) {
				t.Errorf("throttle harus memuat %q; dapat %q", want, got)
			}
		}
	}
}

func TestRunnerFullMode(t *testing.T) {
	if (&Runner{}).mode() != "quick" {
		t.Error("mode default harus quick")
	}
	r := &Runner{Mode: "full"}
	if r.mode() != "full" {
		t.Error("Mode=full harus terbaca")
	}
	r.UseProxy("127.0.0.1:9000")
	args := strings.Join(r.buildFullArgs("/tmp/plan.yaml"), " ")
	for _, want := range []string{"-autorun /tmp/plan.yaml", "network.connection.httpProxy.host=127.0.0.1"} {
		if !strings.Contains(args, want) {
			t.Errorf("full args harus memuat %q; dapat %q", want, args)
		}
	}
	plan := planYAML("https://demo.test", "/out", "report.json")
	for _, want := range []string{
		"activeScan", "spider", "https://demo.test", "traditional-json", `reportFile: "report.json"`,
		// batas waktu wajib ada: tanpa ini active scan bisa tak-hingga di SPA catch-all.
		"maxDuration: 3", "maxScanDurationInMins: 10", "maxRuleDurationInMins: 2",
	} {
		if !strings.Contains(plan, want) {
			t.Errorf("plan harus memuat %q", want)
		}
	}
}
