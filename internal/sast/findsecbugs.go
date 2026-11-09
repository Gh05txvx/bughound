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

// FindSecBugsRunner adalah adapter SAST untuk FindSecBugs (plugin SpotBugs,
// fokus keamanan JVM/Java). BERBEDA dari adapter SAST lain: FindSecBugs
// menganalisis BYTECODE (.jar/.class), bukan source — jadi target harus sudah
// di-compile. Bila tak ada artefak JVM di dir, adapter mengembalikan 0 temuan
// (bukan error). Menjalankan SpotBugs dengan keluaran SARIF lalu menormalkannya
// lewat NormalizeSARIF bersama.
//
// OPT-IN: butuh SpotBugs + JRE + jar plugin findsecbugs (semuanya hanya ada di
// image SAST yang di-build dengan WITH_FINDSECBUGS=true). Tak menyentuh jaringan;
// dikurung ke dir in-scope.
type FindSecBugsRunner struct {
	Bin    string // default "spotbugs"
	Plugin string // path jar plugin findsecbugs; default dari env/konstanta
}

// Name memenuhi Engine.
func (r *FindSecBugsRunner) Name() string { return "findsecbugs" }

// plugin memilih path jar plugin: field → env → default lokasi image.
func (r *FindSecBugsRunner) plugin() string {
	if p := strings.TrimSpace(r.Plugin); p != "" {
		return p
	}
	if p := strings.TrimSpace(os.Getenv("BUGHOUND_FINDSECBUGS_PLUGIN")); p != "" {
		return p
	}
	return "/opt/findsecbugs/findsecbugs-plugin.jar"
}

// args menyusun argumen SpotBugs. -textui non-interaktif; -sarif + -output
// menulis SARIF ke berkas; -pluginList memuat findsecbugs; -effort:max & -low
// memaksimalkan cakupan; targets = jar/dir kelas yang ditemukan.
func (r *FindSecBugsRunner) args(report string, targets []string) []string {
	a := []string{"-textui", "-sarif", "-output", report,
		"-pluginList", r.plugin(), "-effort:max", "-low", "-nested:false"}
	return append(a, targets...)
}

// Analyze menemukan artefak JVM di dir, menjalankan SpotBugs+FindSecBugs, dan
// menormalkan hasil SARIF-nya.
func (r *FindSecBugsRunner) Analyze(ctx context.Context, dir, _, _ string) ([]*finding.Finding, error) {
	targets := discoverJVMTargets(dir, 200)
	if len(targets) == 0 {
		// Tak ada bytecode untuk dianalisis — bukan error (SAST source murni).
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

// parseFindSecBugs menormalkan SARIF SpotBugs + menandai tag "java".
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

// discoverJVMTargets menemukan artefak bytecode di bawah dir: berkas *.jar dan
// direktori yang memuat *.class (induk langsung dari tiap .class, didedup).
// Membatasi jumlah target agar perintah tak meledak. Symlink tak diikuti.
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
