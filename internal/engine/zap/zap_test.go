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
	plain := strings.Join(r.buildPlanArgs("/tmp/plan.yaml", "/tmp/zaprun"), " ")
	// -dir: home ZAP per run (bukan ~/.ZAP bersama) — regresi kebocoran sesi auth
	// lintas run/program via config.xml (live 2026-11-16).
	for _, want := range []string{"-cmd", "-dir /tmp/zaprun", "-autorun /tmp/plan.yaml"} {
		if !strings.Contains(plain, want) {
			t.Errorf("args harus memuat %q; dapat %q", want, plain)
		}
	}
	if strings.Contains(plain, "httpProxy") {
		t.Error("tanpa proxy tak boleh ada config proxy")
	}

	r.UseProxy("127.0.0.1:9000")
	withProxy := strings.Join(r.buildPlanArgs("/tmp/plan.yaml", "/tmp/zaprun"), " ")
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
// host + jeda 1000/20=50ms (berpengaruh pada active scan mode full).
func TestRunnerThrottle(t *testing.T) {
	if plain := strings.Join((&Runner{}).buildPlanArgs("/tmp/plan.yaml", "/tmp/zaprun"), " "); strings.Contains(plain, "scanner.delayInMs") {
		t.Errorf("tanpa RateLimit tak boleh ada throttle; dapat %q", plain)
	}
	got := strings.Join((&Runner{RateLimit: 20}).buildPlanArgs("/tmp/plan.yaml", "/tmp/zaprun"), " ")
	for _, want := range []string{"scanner.threadPerHost=1", "scanner.delayInMs=50"} {
		if !strings.Contains(got, want) {
			t.Errorf("throttle harus memuat %q; dapat %q", want, got)
		}
	}
}

func TestRunnerModes(t *testing.T) {
	if (&Runner{}).mode() != "quick" || (&Runner{}).active() {
		t.Error("mode default harus quick & PASIF (active=false)")
	}
	if (&Runner{Mode: "baseline"}).active() {
		t.Error("baseline harus pasif (active=false)")
	}
	full := &Runner{Mode: "full"}
	if full.mode() != "full" || !full.active() {
		t.Error("Mode=full harus terbaca & aktif")
	}
	full.UseProxy("127.0.0.1:9000")
	args := strings.Join(full.buildPlanArgs("/tmp/plan.yaml", "/tmp/zaprun"), " ")
	for _, want := range []string{"-autorun /tmp/plan.yaml", "network.connection.httpProxy.host=127.0.0.1"} {
		if !strings.Contains(args, want) {
			t.Errorf("args harus memuat %q; dapat %q", want, args)
		}
	}
}

// Jaminan keamanan opsi (a): plan mode PASIF (quick/baseline) TAK PERNAH memuat
// activeScan; plan FULL memuat activeScan, bukan passiveScan-wait. Keduanya tetap
// spider + laporan JSON + batas durasi.
func TestPlanYAMLActiveVsPassive(t *testing.T) {
	common := []string{"spider", "https://demo.test", "traditional-json", `reportFile: "report.json"`, "maxDuration: 3"}

	passive := planYAML("https://demo.test", "/out", "report.json", false, nil)
	for _, want := range append([]string{"passiveScan-wait", "maxDuration: 5"}, common...) {
		if !strings.Contains(passive, want) {
			t.Errorf("plan pasif harus memuat %q", want)
		}
	}
	if strings.Contains(passive, "activeScan") {
		t.Errorf("plan pasif TAK BOLEH memuat activeScan:\n%s", passive)
	}

	active := planYAML("https://demo.test", "/out", "report.json", true, nil)
	for _, want := range append([]string{"activeScan", "maxScanDurationInMins: 10", "maxRuleDurationInMins: 2"}, common...) {
		if !strings.Contains(active, want) {
			t.Errorf("plan aktif harus memuat %q", want)
		}
	}
	if strings.Contains(active, "passiveScan-wait") {
		t.Errorf("plan aktif tak perlu passiveScan-wait:\n%s", active)
	}
}
