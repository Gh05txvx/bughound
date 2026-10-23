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
