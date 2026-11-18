package sast

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"bughound/internal/finding"
)

// FindSecBugsRunner is the SAST adapter for FindSecBugs (a SpotBugs plugin
// focused on JVM/Java security). It DIFFERS from the other SAST adapters:
// FindSecBugs analyzes BYTECODE (.jar/.class), not source, so the target must
// already be compiled. When there are no JVM artifacts in dir, the adapter
// returns 0 findings (not an error). It runs SpotBugs with SARIF output and
// normalizes it through the shared NormalizeSARIF.
//
// OPT-IN: needs SpotBugs + a JRE + the findsecbugs plugin jar (all of them are
// only in the SAST image built with WITH_FINDSECBUGS=true). It does not touch
// the network and is confined to the in-scope dir.
type FindSecBugsRunner struct {
	Bin    string // default "spotbugs"
	Plugin string // path of the findsecbugs plugin jar; defaults to the env/constant
}

// Name implements Engine.
func (r *FindSecBugsRunner) Name() string { return "findsecbugs" }

// plugin picks the plugin jar path: field → env → the image's default location.
func (r *FindSecBugsRunner) plugin() string {
	if p := strings.TrimSpace(r.Plugin); p != "" {
		return p
	}
	if p := strings.TrimSpace(os.Getenv("BUGHOUND_FINDSECBUGS_PLUGIN")); p != "" {
		return p
	}
	return "/opt/findsecbugs/findsecbugs-plugin.jar"
}

// args builds the SpotBugs arguments. -textui is non-interactive; -sarif +
// -output write SARIF to a file; -pluginList loads findsecbugs; -effort:max and
// -low maximize coverage; targets = the jars/class dirs that were found.
func (r *FindSecBugsRunner) args(report string, targets []string) []string {
	a := []string{"-textui", "-sarif", "-output", report,
		"-pluginList", r.plugin(), "-effort:max", "-low", "-nested:false"}
	return append(a, targets...)
}

// Analyze finds JVM artifacts in dir, runs SpotBugs+FindSecBugs and normalizes
// the SARIF result.
func (r *FindSecBugsRunner) Analyze(ctx context.Context, dir, _, _ string) ([]*finding.Finding, error) {
	targets := discoverJVMTargets(dir, 200)
	if len(targets) == 0 {
		// No bytecode to analyze: not an error (pure source SAST).
		return nil, nil
	}
	bin := r.Bin
	if bin == "" {
		bin = "spotbugs"
	}
	tmp, err := os.CreateTemp("", "findsecbugs-*.sarif")
	if err != nil {
		return nil, fmt.Errorf("findsecbugs: temp: %w", err)
	}
	report := tmp.Name()
	tmp.Close()
	defer os.Remove(report)

	cmd := exec.CommandContext(ctx, bin, r.args(report, targets)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	data, rerr := os.ReadFile(report)
	if rerr != nil || len(bytes.TrimSpace(data)) == 0 {
		if runErr != nil {
			return nil, fmt.Errorf("findsecbugs: %v: %s", runErr, strings.TrimSpace(stderr.String()))
		}
		return nil, nil
	}
	return parseFindSecBugs(data)
}

// parseFindSecBugs normalizes SpotBugs SARIF and adds the "java" tag.
func parseFindSecBugs(data []byte) ([]*finding.Finding, error) {
	fs, err := NormalizeSARIF(data, "findsecbugs", nil)
	if err != nil {
		return nil, err
	}
	for _, f := range fs {
		f.Tags = ensureTag(f.Tags, "java")
	}
	return fs, nil
}

// discoverJVMTargets finds bytecode artifacts under dir: *.jar files and
// directories that contain *.class (the direct parent of each .class, deduped).
// It caps the number of targets so the command does not blow up. Symlinks are
// not followed.
func discoverJVMTargets(dir string, max int) []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || len(out) >= max {
			if len(out) >= max {
				return filepath.SkipAll
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".jar":
			add(path)
		case ".class":
			add(filepath.Dir(path))
		}
		return nil
	})
	return out
}

func init() { Register("findsecbugs", func() Engine { return &FindSecBugsRunner{} }) }
