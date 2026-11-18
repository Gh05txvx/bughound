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
			t.Errorf("args must contain %q; got: %s", want, got)
		}
	}
}

func TestRunnerBuildArgsNoProxy(t *testing.T) {
	r := &Runner{}
	got := strings.Join(r.buildArgs("https://demo.test"), " ")
	if strings.Contains(got, "-proxy") {
		t.Errorf("without a proxy there must be no -proxy flag; got: %s", got)
	}
}

func TestRunnerBuildArgsSelection(t *testing.T) {
	// Template selection: tags & severity -> -tags / -severity (comma-joined, trimmed).
	r := &Runner{Tags: []string{"cve", " exposure ", ""}, Severity: []string{"critical", "high"}}
	got := strings.Join(r.buildArgs("https://demo.test"), " ")
	for _, want := range []string{"-tags cve,exposure", "-severity critical,high"} {
		if !strings.Contains(got, want) {
			t.Errorf("args must contain %q; got: %s", want, got)
		}
	}
}

func TestRunnerBuildArgsNoSelection(t *testing.T) {
	// Empty selection -> no -tags/-severity flags (run every template).
	r := &Runner{Tags: []string{"", "  "}, Severity: nil}
	got := strings.Join(r.buildArgs("https://demo.test"), " ")
	// " -tags " (leading space) tells the selection flag apart from "-exclude-tags".
	if strings.Contains(got, " -tags ") || strings.Contains(got, "-severity") {
		t.Errorf("an empty selection must not produce a flag; got: %s", got)
	}
}

// Non-destructive applies to the plain runner too, with or without template selection.
func TestRunnerBuildArgsNonDestructive(t *testing.T) {
	for _, r := range []*Runner{{}, {Tags: []string{"cve"}, Severity: []string{"high"}}} {
		got := strings.Join(r.buildArgs("https://demo.test"), " ")
		for _, want := range []string{"-exclude-tags dos,smuggling", "-exclude-id CVE-2021-30118,CVE-2023-46747"} {
			if !strings.Contains(got, want) {
				t.Errorf("buildArgs does not contain %q; got: %s", want, got)
			}
		}
	}
}

// Custom Payload Bank runner: TemplatesDir -> `-t <dir>` (ONLY custom templates).
func TestRunnerBuildArgsTemplatesDir(t *testing.T) {
	r := &Runner{TemplatesDir: "./templates/custom"}
	got := strings.Join(r.buildArgs("https://demo.test"), " ")
	if !strings.Contains(got, "-t ./templates/custom") {
		t.Errorf("the custom runner must contain -t <dir>; got: %s", got)
	}
	// Non-destructive is still forced even for the custom runner.
	if !strings.Contains(got, "-exclude-tags dos,smuggling") {
		t.Errorf("the custom runner must still be non-destructive; got: %s", got)
	}
}

// Without TemplatesDir (the official nuclei runner) -> NO -t flag (use the full set).
func TestRunnerBuildArgsNoTemplatesDir(t *testing.T) {
	got := strings.Join((&Runner{}).buildArgs("https://demo.test"), " ")
	if strings.Contains(got, " -t ") {
		t.Errorf("the official nuclei runner must not restrict with -t; got: %s", got)
	}
}

// Name() tells the custom runner apart from the official nuclei runner for the roster/log.
func TestRunnerName(t *testing.T) {
	if n := (&Runner{}).Name(); n != "nuclei" {
		t.Errorf("without TemplatesDir Name()=%q, want \"nuclei\"", n)
	}
	if n := (&Runner{TemplatesDir: "  "}).Name(); n != "nuclei" {
		t.Errorf("a whitespace-only TemplatesDir must count as empty, Name()=%q", n)
	}
	if n := (&Runner{TemplatesDir: "./templates/custom"}).Name(); n != "nuclei-custom" {
		t.Errorf("with TemplatesDir Name()=%q, want \"nuclei-custom\"", n)
	}
}
