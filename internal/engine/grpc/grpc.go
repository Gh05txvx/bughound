// Package grpc menormalkan hasil kerja terhadap endpoint gRPC (via grpcurl +
// Server Reflection) ke Skema Temuan Seragam. Dua tingkat:
//   - Scan  : ENUMERASI (reflection) — layanan/metode terekspos.
//   - Fuzz  : enumerasi + INVOKASI metode read-only (payload kosong) untuk
//     mendeteksi metode yang bisa dipanggil tanpa autentikasi (CWE-306).
//
// Keamanan: Fuzz hanya menginvoke metode yang namanya terlihat read-only
// (Get/List/Query/…) agar tak memicu efek samping (Create/Delete/…dilewati).
// Target host:port sudah dipastikan in-scope di hulu (grpcurl tak bisa diproxy).
// Mock tak menyentuh jaringan. Runner opt-in (butuh binary grpcurl).
package grpc

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"bughound/internal/finding"
)

// Scanner adalah engine gRPC: Scan (enumerasi) + Fuzz (enumerasi + invokasi).
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

// Mock adalah engine gRPC palsu (tanpa jaringan).
type Mock struct{}

// Name memenuhi Scanner.
func (Mock) Name() string { return "grpc (mock)" }

// Scan mengembalikan temuan enumerasi sampel.
func (Mock) Scan(_ context.Context, target, program, runID string) ([]*finding.Finding, error) {
	return buildFindings(target, mockServices, mockMethods, true, program, runID), nil
}

// Fuzz mengembalikan enumerasi + contoh metode read-only yang callable tanpa auth.
func (Mock) Fuzz(_ context.Context, target, program, runID string) ([]*finding.Finding, error) {
	out := buildFindings(target, mockServices, mockMethods, true, program, runID)
	out = append(out, fuzzFinding(target, "acme.UserService.ListUsers", "OK", program, runID)...)
	return out, nil
}

// Runner adalah engine gRPC nyata via grpcurl (Server Reflection). Opt-in.
type Runner struct {
	Bin       string // default "grpcurl"
	Plaintext bool   // -plaintext (gRPC tanpa TLS / h2c)
}

// Name memenuhi Scanner.
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

// enumerate menjalankan reflection list (+ per-layanan). reflOK=false bila
// server tak mendukung reflection (bukan error).
func (r *Runner) enumerate(ctx context.Context, target string) (services []string, methods map[string][]string, reflOK bool, err error) {
	out, lerr := runCmd(ctx, r.bin(), r.listArgs(target)...)
	if lerr != nil {
		if strings.Contains(strings.ToLower(out+lerr.Error()), "reflection") {
			return nil, nil, false, nil
		}
		return nil, nil, false, fmt.Errorf("grpc: grpcurl list gagal: %w (%s)", lerr, strings.TrimSpace(out))
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

// Scan: enumerasi saja.
func (r *Runner) Scan(ctx context.Context, target, program, runID string) ([]*finding.Finding, error) {
	services, methods, reflOK, err := r.enumerate(ctx, target)
	if err != nil || !reflOK {
		return nil, err
	}
	return buildFindings(target, services, methods, true, program, runID), nil
}

// Fuzz: enumerasi + invokasi metode read-only dengan payload kosong.
func (r *Runner) Fuzz(ctx context.Context, target, program, runID string) ([]*finding.Finding, error) {
	services, methods, reflOK, err := r.enumerate(ctx, target)
	if err != nil || !reflOK {
		return nil, err
	}
	out := buildFindings(target, services, methods, true, program, runID)
	for _, s := range services {
		for _, m := range methods[s] {
			if !readOnlyMethod(m) {
				continue // lewati metode berpotensi mutasi (default aman)
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

// readOnlyMethod menebak metode read-only dari namanya (konservatif untuk fuzz).
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

// classifyInvoke menerjemahkan hasil grpcurl invoke → kode status gRPC.
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
		out = append(out, mk(target, "grpc-reflection-enabled", "gRPC server reflection aktif", finding.SeverityMedium,
			"Server mengekspos gRPC Server Reflection; skema seluruh layanan/metode dapat dienumerasi tanpa .proto. Nonaktifkan di produksi bila tak diperlukan.",
			"grpc://"+target, "", "CWE-200", program, runID))
	}
	for _, s := range services {
		out = append(out, mk(target, "grpc-service-exposed", "Layanan gRPC terekspos: "+s, finding.SeverityInfo,
			"", "grpc://"+target+"/"+s, s, "", program, runID))
		for _, m := range methods[s] {
			out = append(out, mk(target, "grpc-method-exposed", "Metode gRPC terekspos: "+m, finding.SeverityInfo,
				"", "grpc://"+target+"/"+strings.ReplaceAll(m, ".", "/"), m, "", program, runID))
		}
	}
	return out
}

// fuzzFinding membangun temuan dari hasil invokasi satu metode (atau nil bila
// metode terproteksi: Unauthenticated/PermissionDenied).
func fuzzFinding(target, method, code, program, runID string) []*finding.Finding {
	var sev finding.Severity
	var typ, title, desc string
	switch code {
	case "OK":
		sev, typ = finding.SeverityMedium, "grpc-method-callable-unauth"
		title = "Metode gRPC dapat dipanggil tanpa autentikasi: " + method
		desc = "Invokasi tanpa kredensial (payload kosong) mengembalikan respons sukses — metode tampaknya tak memeriksa autentikasi."
	case "InvalidArgument":
		sev, typ = finding.SeverityLow, "grpc-method-reachable-unauth"
		title = "Metode gRPC terjangkau tanpa autentikasi: " + method
		desc = "Invokasi tanpa kredensial ditolak pada validasi input (InvalidArgument), bukan autentikasi — auth tampaknya tak ditegakkan lebih dulu."
	default:
		return nil // terproteksi atau tak diketahui → tidak dilaporkan
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
