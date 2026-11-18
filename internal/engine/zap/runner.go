package zap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"bughound/internal/engine"
	"bughound/internal/finding"
)

// Runner is the REAL ZAP engine. Two modes, BOTH through the ZAP Automation
// Framework (plan YAML → traditional-json report):
//   - "quick"/"baseline" (default): spider + PASSIVE scan, NO active scan.
//     It sends no attack payload (like zap-baseline): only passive rules
//     (missing headers, version/info leaks, exposed files). Safe & light.
//   - "full": spider + ACTIVE scan (sends payloads: SQLi/XSS/etc.) + report.
//     Deeper coverage, longer, and ACTIVELY ATTACKING — only when
//     started with `-zap-mode full`.
//
// Not the default; needs OWASP ZAP installed. When UseProxy is set, ZAP's connections
// are routed to bughound's egress proxy through the upstream proxy config (scope guard
// per connection). A ZAP invocation is heavy (JVM); args/plan & Parse are tested, real execution
// is used deliberately for a valid target.
type Runner struct {
	Binary      string // default "zap.sh"
	Mode        string // "quick" (default) | "baseline" | "full"
	RateLimit   int    // throttle the active scan: 0 = ZAP default; >0 = 1 thread/host + a ~1000/rate ms gap
	proxyAddr   string
	authHeaders []string // Lever 1: auth headers → a Replacer rule in the plan (see UseAuthHeaders)
}

// Name satisfies engine.Engine.
func (r *Runner) Name() string { return "zap" }

// UseProxy satisfies engine.ProxyAware.
func (r *Runner) UseProxy(addr string) { r.proxyAddr = addr }

// UseAuthHeaders satisfies engine.AuthAware: each "Name: value" header becomes
// a Replacer rule in the plan, so EVERY ZAP request (spider, passive, active)
// carries the login session (Lever 1). The value = secret: it is only written to the plan (0600) &
// ZAP's home per run (config.xml, zap.log) — both in a 0700 temp dir that
// is deleted after the run (see buildPlanArgs).
func (r *Runner) UseAuthHeaders(h []string) { r.authHeaders = h }

func (r *Runner) mode() string {
	switch strings.ToLower(strings.TrimSpace(r.Mode)) {
	case "full":
		return "full"
	case "baseline":
		return "baseline"
	default:
		return "quick"
	}
}

// active marks the mode that sends attack payloads (active scan). ONLY "full".
// quick/baseline are deliberately passive so the default is safe for a bug bounty target.
func (r *Runner) active() bool { return r.mode() == "full" }

// Scan satisfies engine.Engine.
func (r *Runner) Scan(ctx context.Context, target, program, runID string) ([]*finding.Finding, error) {
	bin := r.Binary
	if bin == "" {
		bin = "zap.sh"
	}
	return r.scanPlan(ctx, bin, target, program, runID, r.active())
}

// scanPlan writes the Automation Framework plan (spider + passive, or + active when
// full), runs ZAP, then Parses the JSON report. active=false sends NO
// attack payload at all.
func (r *Runner) scanPlan(ctx context.Context, bin, target, program, runID string, active bool) ([]*finding.Finding, error) {
	dir, err := os.MkdirTemp("", "zap-*")
	if err != nil {
		return nil, fmt.Errorf("zap: temp dir: %w", err)
	}
	defer os.RemoveAll(dir)

	const reportFile = "report.json"
	planPath := filepath.Join(dir, "plan.yaml")
	if err := os.WriteFile(planPath, []byte(planYAML(target, dir, reportFile, active, r.authHeaders)), 0o600); err != nil {
		return nil, fmt.Errorf("zap: write plan: %w", err)
	}
	port, err := freePort()
	if err != nil {
		return nil, fmt.Errorf("zap: port proxy: %w", err)
	}
	reportPath := filepath.Join(dir, reportFile)
	if err := r.run(ctx, bin, append(r.buildPlanArgs(planPath, dir), "-port", port)); err != nil {
		// Exit 2 = the Automation Framework plan finished WITH warnings (e.g. the target
		// replies 401 on every page): its report is valid. Any other exit / no report = failure.
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 2 {
			if fs, rerr := readReport(reportPath, program, runID); rerr == nil {
				return fs, nil
			}
		}
		return nil, err
	}
	return readReport(reportPath, program, runID)
}

// freePort asks the OS for a free local port for ZAP's main proxy: -cmd mode still
// opens that proxy (default 8080), so two concurrent runs fight over the port →
// "BindException Address already in use" (live 2026-11-16). The ZAP docker script
// itself picks a port the same way.
// shortcut: the port can be taken by another process between Close & ZAP's bind (a millisecond window); add a retry if BindException shows up again in the log.
func freePort() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer l.Close()
	return strconv.Itoa(l.Addr().(*net.TCPAddr).Port), nil
}

func (r *Runner) run(ctx context.Context, bin string, args []string) error {
	cmd := exec.CommandContext(ctx, bin, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("zap: execution failed: %w (%s)", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func readReport(path, program, runID string) ([]*finding.Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("zap: read report: %w", err)
	}
	return Parse(bytes.NewReader(data), program, runID)
}

// buildPlanArgs: -dir makes homeDir (a temp dir per run, deleted after the
// run) ZAP's home. ZAP stores run options to its home — including the
// Replacer rule holding the auth header VALUE (config.xml, zap.log, session). A shared home
// (~/.ZAP) makes one program's session carry into the next scan (another
// program) & linger on disk — proven live 2026-11-16.
func (r *Runner) buildPlanArgs(planPath, homeDir string) []string {
	args := append([]string{"-cmd", "-dir", homeDir, "-autorun", planPath}, r.proxyConfigArgs()...)
	return append(args, r.throttleArgs()...)
}

// throttleArgs clamps how aggressive ZAP's active scanner is against the target (RateLimit
// req/s): one thread per host + a ~1000/rate ms gap between requests. It only
// affects full mode (active scan); in quick/baseline (passive) it is a no-op —
// the passive request rate is still clamped by the rate limiter in bughound's egress proxy.
func (r *Runner) throttleArgs() []string {
	if r.RateLimit <= 0 {
		return nil
	}
	delayMs := 1000 / r.RateLimit
	if delayMs < 1 {
		delayMs = 1
	}
	return []string{
		"-config", "scanner.threadPerHost=1",
		"-config", "scanner.delayInMs=" + strconv.Itoa(delayMs),
	}
}

// proxyConfigArgs points ZAP at bughound's egress proxy (when set).
func (r *Runner) proxyConfigArgs() []string {
	if r.proxyAddr == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(r.proxyAddr)
	if err != nil {
		return nil
	}
	return []string{
		"-config", "network.connection.httpProxy.host=" + host,
		"-config", "network.connection.httpProxy.port=" + port,
		"-config", "network.connection.httpProxy.enabled=true",
	}
}

// Plan time limits (minutes). An unlimited active scan can run for hours and
// flood the target — especially on a catch-all SPA whose spider surface is nearly
// infinite. These limits keep the scan finishing & not toppling the target;
// the per-request throttle (throttleArgs) stays on a separate path.
const (
	spiderMaxDurationMin      = 3  // the spider stops after 3 minutes
	passiveWaitMaxDurationMin = 5  // wait for the passive scan queue to drain, at most 5 minutes
	ascanMaxDurationMin       = 10 // total active scan at most 10 minutes (full mode)
	ascanMaxRuleDurMin        = 2  // each active scan rule at most 2 minutes (full mode)
)

// planYAML builds the ZAP Automation Framework plan. Always: spider → (scan job) →
// traditional-json report. The scan job depends on active:
//   - active=false (quick/baseline): passiveScan-wait — wait for the PASSIVE rules to finish,
//     without sending a single attack payload.
//   - active=true (full): activeScan — send payloads (SQLi/XSS/etc.).
//
// The spider & activeScan are duration-limited (see the constants) so they finish on a small
// host and do not flood the target. When there are auth headers, the replacer job (see
// replacerJob) is placed first and the logout route is excluded from the context.
func planYAML(target, reportDir, reportFile string, active bool, authHeaders []string) string {
	replacer, excl := replacerJob(authHeaders), ""
	if replacer != "" {
		// The ZAP spider follows a logout link (live 2026-11-16) → the session dies & the rest of the scan
		// runs silently without login. A URL outside the context is not spidered/scanned.
		excl = "      excludePaths:\n        - " + strconv.Quote(engine.LogoutPattern) + "\n"
	}
	plan := "" +
		"env:\n" +
		"  contexts:\n" +
		"    - name: bughound\n" +
		"      urls: [\"" + target + "\"]\n" +
		excl +
		"  parameters:\n" +
		"    failOnError: false\n" +
		"jobs:\n" +
		replacer +
		"  - type: spider\n" +
		"    parameters:\n" +
		"      context: bughound\n" +
		"      url: \"" + target + "\"\n" +
		"      maxDuration: " + strconv.Itoa(spiderMaxDurationMin) + "\n"
	if active {
		plan += "" +
			"  - type: activeScan\n" +
			"    parameters:\n" +
			"      context: bughound\n" +
			"      maxScanDurationInMins: " + strconv.Itoa(ascanMaxDurationMin) + "\n" +
			"      maxRuleDurationInMins: " + strconv.Itoa(ascanMaxRuleDurMin) + "\n"
	} else {
		plan += "" +
			"  - type: passiveScan-wait\n" +
			"    parameters:\n" +
			"      maxDuration: " + strconv.Itoa(passiveWaitMaxDurationMin) + "\n"
	}
	return plan + "" +
		"  - type: report\n" +
		"    parameters:\n" +
		"      template: traditional-json\n" +
		"      reportDir: \"" + reportDir + "\"\n" +
		"      reportFile: \"" + reportFile + "\"\n"
}

// replacerJob renders the auth headers (Lever 1) into a ZAP Replacer job. Placed
// BEFORE the spider so every job after it carries the header. matchType req_header:
// the header is added when absent, overwritten when present. An empty url & initiators = every
// ZAP request; the bound is still the scope guard at egress, like other engines' `-H`.
// Name & value are strconv.Quote-quoted (Go escaping ⊂ double-quoted YAML escaping), so a
// cookie with `"`/`#`/`:` cannot break or inject into the plan. Without valid headers
// → "" (the plan is unchanged).
func replacerJob(headers []string) string {
	var rules strings.Builder
	n := 0
	for _, h := range headers {
		name, val, ok := strings.Cut(h, ":")
		name, val = strings.TrimSpace(name), strings.TrimSpace(val)
		if !ok || name == "" || val == "" {
			continue // a broken line is skipped; an empty value would REMOVE the header in the Replacer
		}
		n++
		fmt.Fprintf(&rules, "      - description: \"bughound-auth-%d\"\n"+
			"        matchType: req_header\n"+
			"        matchString: %s\n"+
			"        matchRegex: false\n"+
			"        replacementString: %s\n", n, strconv.Quote(name), strconv.Quote(val))
	}
	if n == 0 {
		return ""
	}
	return "  - type: replacer\n    rules:\n" + rules.String()
}
