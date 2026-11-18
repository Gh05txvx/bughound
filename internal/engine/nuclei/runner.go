package nuclei

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"bughound/internal/egress"
	"bughound/internal/engine"
	"bughound/internal/finding"
	"bughound/internal/payload"
)

// Runner is the REAL nuclei engine: it runs the nuclei binary as a subprocess
// then normalizes its JSONL output through Parse.
//
// Outbound connections must go through bughound's egress proxy; the orchestrator
// calls UseProxy before Scan so every nuclei request is checked by the scope
// guard BEFORE the connection is made (internal/egress). This Runner is not the
// default; enable it deliberately and only against a legitimate target (see
// CLAUDE.md: do not run a real scan in a dev/test environment).
type Runner struct {
	Binary    string // default "nuclei"
	RateLimit int    // -rate-limit (req/dtk); 0 = default nuclei
	// Tags & Severity select a SUBSET of templates to run (from the payload bank
	// metadata, BH-SPEC-PAYLOAD §Selection). Empty = run every installed template.
	// -tags and -severity are combined (a template must match both), trimming 14k
	// templates to a targeted subset so the scan is far faster.
	Tags     []string // -tags t1,t2
	Severity []string // -severity critical,high
	// TemplatesDir (optional) restricts nuclei to ONLY this template directory via
	// `-t`, used by the "custom" runner for the Payload Bank (BH-SPEC-PAYLOAD): it
	// runs its own read-only detection templates, SEPARATE from the main runner that
	// runs the full official set. Empty = nuclei's default template set.
	TemplatesDir string
	proxyAddr    string
	authHeaders  []string // Lever 1: auth headers injected via -H (see UseAuthHeaders)
}

// Name satisfies engine.Engine. A Runner with a TemplatesDir is labeled
// "nuclei-custom" so the roster/log tells it apart from the official nuclei runner.
func (r *Runner) Name() string {
	if strings.TrimSpace(r.TemplatesDir) != "" {
		return "nuclei-custom"
	}
	return "nuclei"
}

// UseProxy satisfies engine.ProxyAware: points nuclei at the egress proxy.
func (r *Runner) UseProxy(addr string) { r.proxyAddr = addr }

// UseAuthHeaders satisfies engine.AuthAware: injects the auth headers (-H) into
// every nuclei request so the scan reaches content behind a login (Lever 1).
func (r *Runner) UseAuthHeaders(h []string) { r.authHeaders = h }

// headerArgs renders the auth headers into `-H "Name: value"` arguments (used by
// the plain nuclei runner & -dast). Values are passed to argv as-is (no shell),
// so spaces/`;` in a cookie are safe.
func headerArgs(headers []string) []string {
	a := make([]string, 0, 2*len(headers))
	for _, h := range headers {
		if strings.TrimSpace(h) != "" {
			a = append(a, "-H", h)
		}
	}
	return a
}

// requestPathRE captures a template's request path: `{{BaseURL}}/x` / `{{RootURL}}/x`
// or a raw request line `GET /x HTTP/1.1`.
var requestPathRE = regexp.MustCompile(`(?im)\{\{(?:BaseURL|RootURL)\}\}([^"'\s]*)|^\s*(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)`)

// logoutTemplates returns the templates in dir that request a logout route
// (engine.IsLogoutPath; live 2026-11-16: 32 of ~14k official templates).
// Best-effort: an unreadable dir/file is skipped (nuclei cannot load it either).
func logoutTemplates(dir string) []string {
	var out []string
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".yaml") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		for _, m := range requestPathRE.FindAllSubmatch(b, -1) {
			if engine.IsLogoutPath(string(m[1]) + string(m[2])) {
				out = append(out, p)
				break
			}
		}
		return nil
	})
	return out
}

// Scan satisfies engine.Engine.
func (r *Runner) Scan(ctx context.Context, target, program, runID string) ([]*finding.Finding, error) {
	bin := r.Binary
	if bin == "" {
		bin = "nuclei"
	}
	cmd := exec.CommandContext(ctx, bin, r.buildArgs(target)...)
	if r.proxyAddr != "" {
		cmd.Env = egress.ProxyEnv(os.Environ(), "http://"+r.proxyAddr) // belt-and-suspenders
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("nuclei: execution failed: %w (%s)", err, stderr.String())
	}
	return Parse(&stdout, program, runID)
}

func (r *Runner) buildArgs(target string) []string {
	args := []string{"-jsonl", "-silent", "-disable-update-check", "-target", target}
	if dir := strings.TrimSpace(r.TemplatesDir); dir != "" {
		// Restrict to ONLY the custom templates (the Payload Bank runner). nuclei still
		// applies -tags/-severity & the non-destructive arguments below.
		args = append(args, "-t", dir)
	}
	if r.proxyAddr != "" {
		args = append(args, "-proxy", "http://"+r.proxyAddr)
	}
	if r.RateLimit > 0 {
		args = append(args, "-rate-limit", strconv.Itoa(r.RateLimit))
	}
	if tags := joinNonEmpty(r.Tags); tags != "" {
		args = append(args, "-tags", tags)
	}
	if sev := joinNonEmpty(r.Severity); sev != "" {
		args = append(args, "-severity", sev)
	}
	if h := headerArgs(r.authHeaders); len(h) > 0 { // Lever 1: auth header (if any)
		args = append(args, h...)
		// A template that requests a logout route kills the login session, and nuclei
		// runs FIRST in the roster, so every engine after it ends up without login.
		// shortcut: re-scanned per target (~2s for 14k templates, measured
		// 2026-11-16); cache per Runner if authenticated scans routinely hit hundreds of targets.
		if ex := logoutTemplates(payload.ResolveNucleiDir(r.TemplatesDir)); len(ex) > 0 {
			args = append(args, "-exclude-templates", strings.Join(ex, ","))
		}
	}
	// Structural non-destructive: this applies to the plain runner too, not only
	// -dast. Without it, destructive unsafe templates (smuggling, webshell upload) would run.
	args = append(args, nonDestructiveArgs()...)
	return args
}

// joinNonEmpty joins trimmed non-empty values with commas (the list format
// nuclei's -tags/-severity flags accept); returns "" when there are none.
func joinNonEmpty(in []string) string {
	var out []string
	for _, v := range in {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return strings.Join(out, ",")
}
