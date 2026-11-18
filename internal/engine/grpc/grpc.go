// Package grpc normalizes work against a gRPC endpoint (via grpcurl +
// Server Reflection) to the Uniform Finding Schema. Two levels:
//   - Scan  : ENUMERATION (reflection) — exposed services/methods.
//   - Fuzz  : enumeration + INVOKING read-only methods (empty payload) to
//     detect methods callable without authentication (CWE-306).
//
// Security: Fuzz only invokes a method whose name looks read-only
// (Get/List/Query/…) so it does not trigger side effects (Create/Delete/… are skipped).
// The host:port target is already confirmed in-scope upstream (grpcurl cannot be proxied).
// Mock does not touch the network. Runner is opt-in (needs the grpcurl binary).
package grpc

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"bughound/internal/finding"
)

// Scanner is the gRPC engine: Scan (enumeration) + Fuzz (enumeration + invocation).
type Scanner interface {
	Name() string
	Scan(ctx context.Context, target, program, runID string) ([]*finding.Finding, error)
	Fuzz(ctx context.Context, target, program, runID string) ([]*finding.Finding, error)
}

var mockServices = []string{"acme.UserService", "acme.OrderService"}
var mockMethods = map[string][]string{
	"acme.UserService":  {"acme.UserService.GetUser", "acme.UserService.ListUsers"},
	"acme.OrderService": {"acme.OrderService.CreateOrder"},
}

// Mock is a fake gRPC engine (no network).
type Mock struct{}

// Name satisfies Scanner.
func (Mock) Name() string { return "grpc (mock)" }

// Scan returns sample enumeration findings.
func (Mock) Scan(_ context.Context, target, program, runID string) ([]*finding.Finding, error) {
	return buildFindings(target, mockServices, mockMethods, true, program, runID), nil
}

// Fuzz returns enumeration + a sample read-only method callable without auth.
func (Mock) Fuzz(_ context.Context, target, program, runID string) ([]*finding.Finding, error) {
	out := buildFindings(target, mockServices, mockMethods, true, program, runID)
	out = append(out, fuzzFinding(target, "acme.UserService.ListUsers", "OK", program, runID)...)
	return out, nil
}

// Runner is the real gRPC engine via grpcurl (Server Reflection). Opt-in.
type Runner struct {
	Bin       string // default "grpcurl"
	Plaintext bool   // -plaintext (gRPC without TLS / h2c)
}

// Name satisfies Scanner.
func (r *Runner) Name() string { return "grpc" }

func (r *Runner) bin() string {
	if r.Bin != "" {
		return r.Bin
	}
	return "grpcurl"
}

func (r *Runner) listArgs(target string, extra ...string) []string {
	var args []string
	if r.Plaintext {
		args = append(args, "-plaintext")
	}
	args = append(args, target, "list")
	return append(args, extra...)
}

func (r *Runner) invokeArgs(target, method string) []string {
	var args []string
	if r.Plaintext {
		args = append(args, "-plaintext")
	}
	return append(args, "-d", "{}", target, method)
}

// enumerate runs the reflection list (+ per-service). reflOK=false when the
// server does not support reflection (not an error).
func (r *Runner) enumerate(ctx context.Context, target string) (services []string, methods map[string][]string, reflOK bool, err error) {
	out, lerr := runCmd(ctx, r.bin(), r.listArgs(target)...)
	if lerr != nil {
		if strings.Contains(strings.ToLower(out+lerr.Error()), "reflection") {
			return nil, nil, false, nil
		}
		return nil, nil, false, fmt.Errorf("grpc: grpcurl list failed: %w (%s)", lerr, strings.TrimSpace(out))
	}
	services = appServices(parseList(out))
	methods = map[string][]string{}
	for _, s := range services {
		if mOut, merr := runCmd(ctx, r.bin(), r.listArgs(target, s)...); merr == nil {
			methods[s] = parseList(mOut)
		}
	}
	return services, methods, true, nil
}

// Scan: enumeration only.
func (r *Runner) Scan(ctx context.Context, target, program, runID string) ([]*finding.Finding, error) {
	services, methods, reflOK, err := r.enumerate(ctx, target)
	if err != nil || !reflOK {
		return nil, err
	}
	return buildFindings(target, services, methods, true, program, runID), nil
}

// Fuzz: enumeration + invoking read-only methods with an empty payload.
func (r *Runner) Fuzz(ctx context.Context, target, program, runID string) ([]*finding.Finding, error) {
	services, methods, reflOK, err := r.enumerate(ctx, target)
	if err != nil || !reflOK {
		return nil, err
	}
	out := buildFindings(target, services, methods, true, program, runID)
	for _, s := range services {
		for _, m := range methods[s] {
			if !readOnlyMethod(m) {
				continue // skip a potentially mutating method (safe default)
			}
			code := classifyInvoke(runCmd(ctx, r.bin(), r.invokeArgs(target, m)...))
			out = append(out, fuzzFinding(target, m, code, program, runID)...)
		}
	}
	return out, nil
}

func parseList(out string) []string {
	var lines []string
	for _, ln := range strings.Split(out, "\n") {
		if ln = strings.TrimSpace(ln); ln != "" {
			lines = append(lines, ln)
		}
	}
	return lines
}

func appServices(all []string) []string {
	var out []string
	for _, s := range all {
		ls := strings.ToLower(s)
		if strings.HasPrefix(ls, "grpc.reflection.") || strings.HasPrefix(ls, "grpc.health.") || strings.HasPrefix(ls, "grpc.channelz.") {
			continue
		}
		out = append(out, s)
	}
	return out
}

// readOnlyMethod guesses a read-only method from its name (conservative for fuzz).
var readVerbs = []string{"get", "list", "query", "search", "describe", "fetch", "read", "watch", "check", "health", "lookup", "status", "info"}

func readOnlyMethod(fq string) bool {
	name := fq
	if i := strings.LastIndex(fq, "."); i >= 0 {
		name = fq[i+1:]
	}
	name = strings.ToLower(name)
	for _, v := range readVerbs {
		if strings.HasPrefix(name, v) {
			return true
		}
	}
	return false
}

// classifyInvoke translates the grpcurl invoke result → gRPC status code.
func classifyInvoke(out string, err error) string {
	if err == nil {
		return "OK"
	}
	i := strings.Index(out, "Code:")
	if i < 0 {
		return "Unknown"
	}
	line := out[i+len("Code:"):]
	if nl := strings.IndexAny(line, "\r\n"); nl >= 0 {
		line = line[:nl]
	}
	return strings.TrimSpace(line)
}

func buildFindings(target string, services []string, methods map[string][]string, reflectionOK bool, program, runID string) []*finding.Finding {
	var out []*finding.Finding
	if reflectionOK {
		out = append(out, mk(target, "grpc-reflection-enabled", "gRPC server reflection enabled", finding.SeverityMedium,
			"The server exposes gRPC Server Reflection; the full service/method schema can be enumerated without a .proto. Disable it in production if not needed.",
			"grpc://"+target, "", "CWE-200", program, runID))
	}
	for _, s := range services {
		out = append(out, mk(target, "grpc-service-exposed", "Exposed gRPC service: "+s, finding.SeverityInfo,
			"", "grpc://"+target+"/"+s, s, "", program, runID))
		for _, m := range methods[s] {
			out = append(out, mk(target, "grpc-method-exposed", "Exposed gRPC method: "+m, finding.SeverityInfo,
				"", "grpc://"+target+"/"+strings.ReplaceAll(m, ".", "/"), m, "", program, runID))
		}
	}
	return out
}

// fuzzFinding builds a finding from one method's invoke result (or nil when the
// method is protected: Unauthenticated/PermissionDenied).
func fuzzFinding(target, method, code, program, runID string) []*finding.Finding {
	var sev finding.Severity
	var typ, title, desc string
	switch code {
	case "OK":
		sev, typ = finding.SeverityMedium, "grpc-method-callable-unauth"
		title = "A gRPC method can be called without authentication: " + method
		desc = "Invoking without credentials (empty payload) returned a success response — the method appears not to check authentication."
	case "InvalidArgument":
		sev, typ = finding.SeverityLow, "grpc-method-reachable-unauth"
		title = "A gRPC method is reachable without authentication: " + method
		desc = "Invoking without credentials was rejected at input validation (InvalidArgument), not authentication — auth appears not to be enforced first."
	default:
		return nil // protected or unknown → not reported
	}
	f := mk(target, typ, title, sev, desc, "grpc://"+target+"/"+strings.ReplaceAll(method, ".", "/"), "grpc status: "+code, "CWE-306", program, runID)
	f.Confidence = finding.ConfidenceMedium
	f.Evidence.Payload = "{}"
	f.Tags = []string{"grpc", "auth"}
	return []*finding.Finding{f}
}

func mk(target, typ, title string, sev finding.Severity, desc, url, matched, cwe, program, runID string) *finding.Finding {
	f := &finding.Finding{
		Program: program, RunID: runID, Target: target,
		Type: typ, Title: title, Description: desc,
		Severity: sev, Confidence: finding.ConfidenceHigh, Status: finding.StatusNew,
		SourceEngine: "grpc", Location: finding.Location{URL: url}, Tags: []string{"grpc"},
	}
	if matched != "" {
		f.Evidence = &finding.Evidence{Matched: matched}
	}
	if cwe != "" {
		f.CWE = []string{cwe}
	}
	return f
}

func runCmd(ctx context.Context, bin string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String() + stderr.String(), err
	}
	return stdout.String(), nil
}
