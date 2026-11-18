package ffuf

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"bughound/internal/egress"
	"bughound/internal/finding"
)

// Runner is the REAL ffuf engine: it runs the ffuf binary as a subprocess,
// writes the JSON result to a temp file, then normalizes it through Parse.
//
// The wordlist is optional: if empty, the built-in wordlist is used
// (defaultWordlist). Outbound connections must go through bughound's egress proxy
// (UseProxy -> ffuf -x), so every request is checked by the scope guard BEFORE
// the connection is made. Not the default; enable it deliberately for a legitimate target.
type Runner struct {
	Binary      string // default "ffuf"
	Wordlist    string // -w; empty = built-in wordlist
	RateLimit   int    // -rate (req/dtk); 0 = default ffuf
	APIRoutes   bool   // true = add the bundled API route wordlist (Assetnote apiroutes)
	proxyAddr   string
	authHeaders []string // Lever 1: auth headers injected via -H (see UseAuthHeaders)
}

// Name satisfies engine.Engine.
func (r *Runner) Name() string { return "ffuf" }

// UseProxy satisfies engine.ProxyAware: points ffuf at the egress proxy.
func (r *Runner) UseProxy(addr string) { r.proxyAddr = addr }

// UseAuthHeaders satisfies engine.AuthAware: injects the auth headers (-H) into
// every ffuf request so content fuzzing works behind a login (Lever 1).
func (r *Runner) UseAuthHeaders(h []string) { r.authHeaders = h }

// Scan satisfies engine.Engine.
func (r *Runner) Scan(ctx context.Context, target, program, runID string) ([]*finding.Finding, error) {
	bin := r.Binary
	if bin == "" {
		bin = "ffuf"
	}
	wordlist, cleanupWL, err := r.resolveWordlist()
	if err != nil {
		return nil, fmt.Errorf("ffuf: wordlist: %w", err)
	}
	defer func() { cleanupWL() }() // closure: also cleans up the replacement when the wordlist is merged

	// Enrichment (best-effort, through the scope-enforced egress proxy): paths the
	// target advertises via robots.txt (Disallow/Allow) plus endpoints documented in
	// an OpenAPI/Swagger spec are high-value probe candidates (e.g. /ftp,
	// /b2b/v2/orders). Every resulting path is still probed by ffuf through the same
	// proxy. A failure or absence means no enrichment, not an error.
	var extra []string
	extra = append(extra, r.robotsPaths(ctx, target)...)
	extra = append(extra, r.specPaths(ctx, target)...)
	extra = append(extra, r.apiRoutePaths()...) // bundled API routes (opt-in, through the proxy)
	if len(extra) > 0 {
		if merged, cleanupMerged, mErr := mergeWordlist(wordlist, extra); mErr == nil {
			cleanupWL() // drop the base wordlist
			wordlist, cleanupWL = merged, cleanupMerged
		}
	}
	if len(r.authHeaders) > 0 {
		// Authenticated scan: drop logout route entries (the session dies; live
		// 2026-11-16). Fail-closed: if filtering fails, do not fuzz with the session at all.
		filtered, cleanupF, fErr := withoutLogout(wordlist)
		if fErr != nil {
			return nil, fmt.Errorf("ffuf: filter logout wordlist: %w", fErr)
		}
		cleanupWL()
		wordlist, cleanupWL = filtered, cleanupF
	}

	tmp, err := os.CreateTemp("", "ffuf-*.json")
	if err != nil {
		return nil, fmt.Errorf("ffuf: temp file: %w", err)
	}
	out := tmp.Name()
	tmp.Close()
	defer os.Remove(out)

	// ffuf v2 stores each run's options, INCLUDING the -H header value (the auth
	// session), in plaintext at $XDG_CONFIG_HOME/ffuf/history. A shared config home
	// means secrets pile up across programs in the container (proven live
	// 2026-11-16), so a dir per run.
	cfgDir, err := os.MkdirTemp("", "ffuf-cfg-*")
	if err != nil {
		return nil, fmt.Errorf("ffuf: temp config dir: %w", err)
	}
	defer os.RemoveAll(cfgDir)

	cmd := exec.CommandContext(ctx, bin, r.buildArgs(target, out, wordlist)...)
	env := os.Environ()
	if r.proxyAddr != "" {
		env = egress.ProxyEnv(env, "http://"+r.proxyAddr) // belt-and-suspenders
	}
	cmd.Env = append(env, "XDG_CONFIG_HOME="+cfgDir) // the last env entry wins
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ffuf: execution failed: %w (%s)", err, strings.TrimSpace(stderr.String()))
	}
	data, err := os.ReadFile(out)
	if err != nil {
		return nil, fmt.Errorf("ffuf: read result: %w", err)
	}
	return Parse(bytes.NewReader(data), program, runID)
}

func (r *Runner) buildArgs(target, out, wordlist string) []string {
	u := target
	if !strings.Contains(u, "FUZZ") {
		u = strings.TrimRight(u, "/") + "/FUZZ"
	}
	// -ac: ffuf auto-calibration. ffuf probes a few random paths first to learn the
	// catch-all response "fingerprint" (e.g. an SPA that answers index.html for
	// nearly every path) then filters it AT THE SOURCE. This cuts the flood of false
	// positives while also reducing requests to the target. Parse() still has its own
	// suppression layer as a safety net.
	args := []string{"-u", u, "-w", wordlist, "-of", "json", "-o", out, "-s", "-ac"}
	if r.proxyAddr != "" {
		args = append(args, "-x", "http://"+r.proxyAddr)
	}
	if r.RateLimit > 0 {
		args = append(args, "-rate", strconv.Itoa(r.RateLimit))
	}
	for _, h := range r.authHeaders { // Lever 1: auth header (if any)
		if strings.TrimSpace(h) != "" {
			args = append(args, "-H", h)
		}
	}
	return args
}
