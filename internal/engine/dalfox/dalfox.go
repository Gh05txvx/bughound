// Package dalfox wraps dalfox (hahwul/dalfox) as an ACTIVE DAST engine
// specialized in XSS behind the uniform engine contract. It sends XSS payloads to
// target parameters, then normalizes the PoC it finds to the Uniform Finding Schema
// (BH-SPEC-FINDING), like the other engines.
//
// Security (sensitive area): EVERY request goes through the scope-enforced egress proxy —
// dalfox runs with --proxy pointing at bughound's proxy, so each outbound
// connection is checked by the scope guard (a payload only changes a parameter VALUE;
// the host stays in-scope; blind/OAST to a third party is blocked by the proxy). Fail-safe: without a
// proxy, there is NO connection at all. Volume is capped by workers + delay (stealth).
// Non-destructive: dalfox tests XSS reflection/execution, it performs no
// destructive action. A finding = a CANDIDATE (draft→manual verify), in line with bughound's philosophy.
package dalfox

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

// Runner is the real dalfox adapter (OPT-IN; needs the dalfox binary on PATH).
type Runner struct {
	Binary      string // default "dalfox"
	RateLimit   int    // approximate rate → mapped to --delay (ms) when > 0
	Stealth     bool   // low-and-slow: fewer workers + delay
	proxyAddr   string
	authHeaders []string // Lever 1: auth headers injected via -H (see UseAuthHeaders)
}

// Name satisfies engine.Engine.
func (r *Runner) Name() string { return "dalfox" }

// UseProxy satisfies engine.ProxyAware: every dalfox request goes through the egress proxy.
func (r *Runner) UseProxy(addr string) { r.proxyAddr = addr }

// UseAuthHeaders satisfies engine.AuthAware: injects auth headers (-H) into every
// dalfox request so XSS is tested behind a login (Lever 1).
func (r *Runner) UseAuthHeaders(h []string) { r.authHeaders = h }

// Scan satisfies engine.Engine: run dalfox against the target, then normalize the PoC.
func (r *Runner) Scan(ctx context.Context, target, program, runID string) ([]*finding.Finding, error) {
	// Fail-safe: without the egress proxy, make NO connection at all (in line with the
	// principle "never trigger a connection that bypasses the scope guard").
	if r.proxyAddr == "" {
		return nil, nil
	}

	outFile, err := os.CreateTemp("", "dalfox-*.json")
	if err != nil {
		return nil, fmt.Errorf("dalfox: output file: %w", err)
	}
	outPath := outFile.Name()
	_ = outFile.Close()
	defer os.Remove(outPath)

	bin := r.Binary
	if bin == "" {
		bin = "dalfox"
	}
	cmd := exec.CommandContext(ctx, bin, r.args(target, outPath)...)
	cmd.Env = egress.ProxyEnv(os.Environ(), "http://"+r.proxyAddr) // belt-and-suspenders
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	// Read the result from the output file first: dalfox writes the PoC there
	// regardless of the exit code. If there are findings, return them even on a non-zero exit
	// (tolerant of dalfox's exit quirk); if empty & there is an error, report the error.
	data, _ := os.ReadFile(outPath)
	fs, perr := Parse(bytes.NewReader(data), target, program, runID)
	if perr != nil {
		if runErr != nil {
			return nil, fmt.Errorf("dalfox: execution failed: %w (%s)", runErr, strings.TrimSpace(stderr.String()))
		}
		return nil, fmt.Errorf("dalfox: parse: %w", perr)
	}
	if len(fs) == 0 && runErr != nil {
		return nil, fmt.Errorf("dalfox: execution failed: %w (%s)", runErr, strings.TrimSpace(stderr.String()))
	}
	return fs, nil
}

// args assembles the dalfox arguments (separated so they can be tested without executing).
// JSON output is written to a file (a clean parse, free of stdout noise); every
// request is routed to the egress proxy; workers/delay cap the volume.
func (r *Runner) args(target, outPath string) []string {
	a := []string{
		"url", target,
		"--format", "json",
		"--output", outPath,
		"--output-request",  // include the raw HTTP request → Evidence.Request (Burp-ready)
		"--output-response", // include the raw HTTP response → Evidence.ResponseExcerpt
		"--silence",
		"--no-spinner",
		"--no-color",
		"--proxy", "http://" + r.proxyAddr,
		"--timeout", "10",
		"--worker", strconv.Itoa(r.workers()),
	}
	if d := r.delayMS(); d > 0 {
		a = append(a, "--delay", strconv.Itoa(d))
	}
	for _, h := range r.authHeaders { // Lever 1: auth headers (if any)
		if strings.TrimSpace(h) != "" {
			a = append(a, "-H", h)
		}
	}
	return a
}

// workers sets dalfox concurrency: lower under stealth (minimal footprint).
func (r *Runner) workers() int {
	if r.Stealth {
		return 10
	}
	return 40
}

// delayMS sets the gap between requests (ms): from RateLimit when set, then
// the default stealth gap, otherwise 0 (no extra gap).
func (r *Runner) delayMS() int {
	if r.RateLimit > 0 {
		ms := 1000 / r.RateLimit
		if ms < 1 {
			ms = 1
		}
		return ms
	}
	if r.Stealth {
		return 200
	}
	return 0
}
