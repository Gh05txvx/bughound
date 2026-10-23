// Package grpc menormalkan enumerasi gRPC (via grpcurl + Server Reflection) ke
// Skema Temuan Seragam: reflection yang aktif + layanan/metode yang terenumerasi
// dilaporkan sebagai temuan. Target berupa "host:port" (bukan URL HTTP).
//
// Menyediakan Mock (tanpa jaringan) dan Runner nyata (subprocess grpcurl).
// Cakupan saat ini = ENUMERASI (reflection), belum fuzzing invokasi metode —
// itu langkah lanjutan terpisah. grpcurl tak diproxy; scope ditegakkan di hulu
// (host target dicek sebelum Scan).
package grpc

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"bughound/internal/finding"
)

// Mock adalah engine gRPC palsu: data reflection sampel, tanpa jaringan.
type Mock struct{}

// Name memenuhi engine.Engine.
func (Mock) Name() string { return "grpc (mock)" }

// Scan memenuhi engine.Engine.
func (Mock) Scan(_ context.Context, target, program, runID string) ([]*finding.Finding, error) {
	services := []string{"acme.UserService", "acme.OrderService"}
	methods := map[string][]string{
		"acme.UserService":  {"acme.UserService.GetUser", "acme.UserService.ListUsers"},
		"acme.OrderService": {"acme.OrderService.CreateOrder"},
	}
	return buildFindings(target, services, methods, true, program, runID), nil
}

// Runner adalah engine gRPC nyata via grpcurl (Server Reflection). Opt-in.
type Runner struct {
	Bin       string // default "grpcurl"
	Plaintext bool   // -plaintext (gRPC tanpa TLS / h2c)
}

// Name memenuhi engine.Engine.
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

// Scan menjalankan grpcurl list (+ per-layanan) dan menormalkan hasilnya.
func (r *Runner) Scan(ctx context.Context, target, program, runID string) ([]*finding.Finding, error) {
	out, err := runCmd(ctx, r.bin(), r.listArgs(target)...)
	if err != nil {
		// Reflection tak didukung → tak ada temuan enumerasi (bukan error fatal).
		if strings.Contains(strings.ToLower(out+err.Error()), "reflection") {
			return nil, nil
		}
		return nil, fmt.Errorf("grpc: grpcurl list gagal: %w (%s)", err, strings.TrimSpace(out))
	}
	services := appServices(parseList(out))
	methods := map[string][]string{}
	for _, s := range services {
		if mOut, merr := runCmd(ctx, r.bin(), r.listArgs(target, s)...); merr == nil {
			methods[s] = parseList(mOut)
		}
	}
	return buildFindings(target, services, methods, true, program, runID), nil
}

// parseList: satu nama per baris, buang kosong.
func parseList(out string) []string {
	var lines []string
	for _, ln := range strings.Split(out, "\n") {
		if ln = strings.TrimSpace(ln); ln != "" {
			lines = append(lines, ln)
		}
	}
	return lines
}

// appServices menyaring layanan infra (reflection/health/channelz) dari daftar.
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

func buildFindings(target string, services []string, methods map[string][]string, reflectionOK bool, program, runID string) []*finding.Finding {
	mk := func(typ, title string, sev finding.Severity, desc, url, matched, cwe string) *finding.Finding {
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
	var out []*finding.Finding
	if reflectionOK {
		out = append(out, mk("grpc-reflection-enabled", "gRPC server reflection aktif", finding.SeverityMedium,
			"Server mengekspos gRPC Server Reflection; skema seluruh layanan/metode dapat dienumerasi tanpa .proto. Nonaktifkan di produksi bila tak diperlukan.",
			"grpc://"+target, "", "CWE-200"))
	}
	for _, s := range services {
		out = append(out, mk("grpc-service-exposed", "Layanan gRPC terekspos: "+s, finding.SeverityInfo,
			"", "grpc://"+target+"/"+s, s, ""))
		for _, m := range methods[s] {
			out = append(out, mk("grpc-method-exposed", "Metode gRPC terekspos: "+m, finding.SeverityInfo,
				"", "grpc://"+target+"/"+strings.ReplaceAll(m, ".", "/"), m, ""))
		}
	}
	return out
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
