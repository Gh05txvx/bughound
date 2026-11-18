// Package orchestrator ties the scope guard, (optional) recon, the DAST
// engines, the rate limiter and the store into one scan flow.
//
// Two structural guarantees (BH-SPEC-SCOPE + bughound principles):
//   - The scope guard is the ONLY decision point, enforced at two layers: at
//     input/planning time and at egress (before a finding is accepted). Assets
//     from recon must pass the scope guard too; recon does not bypass scope.
//   - The rate limiter IS IN THE EXECUTION PATH: every recon call and every
//     scan waits for a token first, and the limiter cannot be turned off.
package orchestrator

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"bughound/internal/egress"
	"bughound/internal/engine"
	"bughound/internal/ratelimit"
	"bughound/internal/recon"
	"bughound/internal/scope"
	"bughound/internal/store"
)

// Layer marks the scope enforcement layer.
type Layer string

const (
	LayerInput   Layer = "input"   // at planning time, before the scan queue
	LayerEgress  Layer = "egress"  // right before an outbound connection: the request is blocked
	LayerFinding Layer = "finding" // a finding dropped after the engine finished: not proof that its connection was blocked
)

// AuditEvent is one audit trail entry for a scope decision.
type AuditEvent struct {
	Time         time.Time
	Program      string
	RunID        string
	Target       string
	Allowed      bool
	Reason       scope.Reason
	Layer        Layer
	MatchedEntry string
}

// Orchestrator runs scans for one program.
type Orchestrator struct {
	guard   *scope.Guard
	engines []engine.Engine
	store   store.Store
	lim     *ratelimit.Limiter
	recon   recon.Engine // optional
	audit   func(AuditEvent)
	now     func() time.Time
}

// New creates an Orchestrator. audit may be nil (it becomes a no-op). lim may
// be nil, but that does NOT turn limiting off: nil is replaced with a safe
// default limiter (the rate limiter is always in the execution path).
func New(guard *scope.Guard, eng engine.Engine, st store.Store, lim *ratelimit.Limiter, audit func(AuditEvent)) *Orchestrator {
	if audit == nil {
		audit = func(AuditEvent) {}
	}
	if lim == nil {
		lim = ratelimit.New(ratelimit.Config{})
	}
	return &Orchestrator{guard: guard, engines: []engine.Engine{eng}, store: st, lim: lim, audit: audit, now: time.Now}
}

// UseRecon enables the (optional) recon stage.
func (o *Orchestrator) UseRecon(r recon.Engine) { o.recon = r }

// AddEngine adds another DAST engine. Every engine runs per target and writes
// to the same finding schema.
func (o *Orchestrator) AddEngine(e engine.Engine) { o.engines = append(o.engines, e) }

// ProxyChain is the upstream proxy chain (hops in order). String redacts the
// credentials (userinfo), so the chain never prints user:pass when it is
// logged or formatted (safe by construction; Principle #5).
type ProxyChain []string

func (pc ProxyChain) String() string {
	s := "["
	for i, raw := range pc {
		if i > 0 {
			s += " "
		}
		s += egress.RedactProxyURL(raw)
	}
	return s + "]"
}

// AuthHeaders is the list of authentication headers (e.g. "Cookie:
// session=...", "Authorization: Bearer ...") injected into EVERY engine request
// so the scan reaches content behind a login (Lever 1: authenticated
// scanning). Each element has the form "Name: value".
//
// The header VALUE is a secret. String() redacts the value (the name stays),
// so credentials are never printed when the list is logged or formatted (safe
// by construction; Principle #5). The orchestrator also redacts these values
// from finding evidence before saving. The headers only ride on requests that
// pass the scope guard; a redirect out of scope is still denied at egress, so
// credentials do not leak out of scope.
type AuthHeaders []string

func (ah AuthHeaders) String() string {
	s := "["
	for i, raw := range ah {
		if i > 0 {
			s += " "
		}
		s += redactHeader(raw)
	}
	return s + "]"
}

// Names returns the NAME of each header (the part before ':'), used to redact
// evidence. Values are never included.
func (ah AuthHeaders) Names() []string {
	if len(ah) == 0 {
		return nil
	}
	names := make([]string, 0, len(ah))
	for _, h := range ah {
		if name, _, ok := strings.Cut(h, ":"); ok {
			if n := strings.TrimSpace(name); n != "" {
				names = append(names, n)
			}
		}
	}
	return names
}

// Scrub replaces each header VALUE in s with [REDACTED] (longest first, so a
// value that contains another value is not left partly visible). It is applied
// to engine/recon error text before it enters the (append-only) audit and the
// run summary: a third-party tool can echo an argv/config holding header values
// to its stderr.
func (ah AuthHeaders) Scrub(s string) string {
	vals := make([]string, 0, len(ah))
	for _, h := range ah {
		if _, v, ok := strings.Cut(h, ":"); ok && strings.TrimSpace(v) != "" {
			vals = append(vals, strings.TrimSpace(v))
		}
	}
	sort.Slice(vals, func(i, j int) bool { return len(vals[i]) > len(vals[j]) })
	for _, v := range vals {
		s = strings.ReplaceAll(s, v, "[REDACTED]")
	}
	return s
}

// redactHeader keeps the header name and masks its value.
func redactHeader(h string) string {
	name, _, ok := strings.Cut(h, ":")
	if !ok || strings.TrimSpace(name) == "" {
		return "***"
	}
	return strings.TrimSpace(name) + ": ***"
}

// ScanRequest asks for a scan of one program.
type ScanRequest struct {
	Program string
	RunID   string   // generated when empty
	Seeds   []string // starting domains for recon (optional)
	Targets []string // explicit targets
	// ProxyChain (optional): engine outbound connections are forwarded through
	// this proxy chain (hops in order) AFTER they pass the scope guard
	// (http/https/socks5). Empty = dial directly.
	ProxyChain ProxyChain
	// OpenAPISpec (optional): the raw content of an OpenAPI/Swagger spec. When
	// set, it is handed to OpenAPIAware engines so requests (including bodies) are
	// generated from the spec and fuzzed. Every connection still goes through the
	// egress proxy (the scope guard enforces it).
	OpenAPISpec []byte
	// AuthHeaders (optional): authentication headers (Cookie/Authorization/etc.)
	// injected into every request of AuthAware engines so the scan reaches
	// content behind a login (Lever 1). The value is a secret: it is redacted
	// when formatted or logged and removed from evidence before saving; it never
	// enters a finding or report. The headers only ride on requests that pass
	// the scope guard.
	AuthHeaders AuthHeaders
}

// ScanResult summarizes the result of one run.
type ScanResult struct {
	RunID         string
	Discovered    int          // assets from recon
	Scanned       []string     // in-scope targets that were scanned (normalized)
	Denied        []AuditEvent // targets/findings the guard denied (input/egress)
	FindingsSaved int
	Duplicates    int
	EngineErrors  []EngineError // engines that failed on a target (the run carries on)
}

// EngineError records one engine that failed on one target. It is not fatal:
// the run carries on with the other engines/targets so their findings are
// still collected and saved.
type EngineError struct {
	Engine string
	Target string
	Err    string
}

// RunScan runs recon (when enabled), enforces the scope guard + rate limiter,
// runs the engines against in-scope targets, re-checks every finding at the
// egress layer and saves the ones that pass.
func (o *Orchestrator) RunScan(ctx context.Context, req ScanRequest) (ScanResult, error) {
	if req.Program == "" {
		return ScanResult{}, fmt.Errorf("orchestrator: program is required")
	}
	runID := req.RunID
	if runID == "" {
		runID = "run_" + o.now().UTC().Format("20060102_150405")
	}
	res := ScanResult{RunID: runID}

	// Egress proxy: when there is an external engine (ProxyAware), start the
	// scope-enforcing proxy for this run and point the engines at it, so every
	// outbound engine connection is checked BEFORE it is made. Fail closed: if
	// the proxy cannot start, external engines are not run.
	var egressMu sync.Mutex
	var egressDenied []AuditEvent
	if o.needsEgressProxy() {
		px := egress.New(o.guard, func(d egress.Decision) {
			if d.Allowed {
				return
			}
			ev := AuditEvent{Time: o.now().UTC(), Program: req.Program, RunID: runID, Target: d.Target, Allowed: false, Reason: d.Reason, Layer: LayerEgress}
			o.audit(ev)
			egressMu.Lock()
			egressDenied = append(egressDenied, ev)
			egressMu.Unlock()
		})
		if len(req.ProxyChain) > 0 {
			if err := px.SetUpstream(req.ProxyChain...); err != nil {
				return res, fmt.Errorf("orchestrator: invalid proxy chain (fail closed): %w", err)
			}
		}
		addr, stop, err := px.Listen("127.0.0.1:0")
		if err != nil {
			return res, fmt.Errorf("orchestrator: cannot start the egress proxy (fail closed): %w", err)
		}
		defer stop()
		for _, eng := range o.engines {
			if pa, ok := eng.(engine.ProxyAware); ok {
				pa.UseProxy(addr)
			}
		}
		if pa, ok := o.recon.(engine.ProxyAware); ok {
			pa.UseProxy(addr) // active recon (httpx/katana) is scope-enforced too
		}
	}

	// The OpenAPI/Swagger spec (when present) is handed to the engines that
	// support it so requests, including bodies, are generated from the spec.
	// Egress still goes through the proxy.
	if len(req.OpenAPISpec) > 0 {
		for _, eng := range o.engines {
			if oa, ok := eng.(engine.OpenAPIAware); ok {
				oa.UseOpenAPISpec(req.OpenAPISpec)
			}
		}
	}

	// The authentication headers (when present) are handed to the engines and
	// recon that support them so the scan and crawl reach content behind a login
	// (Lever 1). SECURITY: the headers only ride on requests that pass the scope
	// guard; a redirect out of scope is still denied at egress (credentials do
	// not leak out of scope). Values are redacted from evidence before saving
	// (authNames) and are never printed.
	authNames := req.AuthHeaders.Names()
	if len(req.AuthHeaders) > 0 {
		for _, eng := range o.engines {
			if aa, ok := eng.(engine.AuthAware); ok {
				aa.UseAuthHeaders([]string(req.AuthHeaders))
			}
		}
		if aa, ok := o.recon.(engine.AuthAware); ok {
			aa.UseAuthHeaders([]string(req.AuthHeaders))
		}
	}

	candidates := append([]string{}, req.Targets...)

	// Recon stage (optional). The rate limiter limits its call too.
	if o.recon != nil && len(req.Seeds) > 0 {
		if err := o.lim.Wait(ctx); err != nil {
			return res, fmt.Errorf("orchestrator: rate limit (recon): %w", err)
		}
		assets, err := o.recon.Discover(ctx, req.Seeds)
		if err != nil {
			return res, fmt.Errorf("orchestrator: recon %s failed: %s", o.recon.Name(), req.AuthHeaders.Scrub(err.Error()))
		}
		for _, a := range assets {
			res.Discovered++
			candidates = append(candidates, a.Value)
		}
	}

	// DAST stage over the in-scope candidates.
	seen := map[string]bool{}
	for _, target := range candidates {
		if target == "" || seen[target] {
			continue
		}
		seen[target] = true
		// Lever 1: logout routes (from recon, OpenAPI spec endpoints or targets) are
		// not scanned during a logged-in scan: one GET kills the session and the rest
		// of the scan silently runs without a login.
		if len(authNames) > 0 && engine.IsLogoutURL(target) {
			continue
		}

		// Layer 1: enforcement at input/planning time.
		d := o.guard.Evaluate(target)
		ev := o.auditEvent(req.Program, runID, d, LayerInput)
		o.audit(ev)
		if !d.Allowed {
			res.Denied = append(res.Denied, ev)
			continue
		}
		res.Scanned = append(res.Scanned, d.Target)

		// Run every engine against this target. The rate limiter is in the
		// execution path: wait for a token before each engine call.
		for _, eng := range o.engines {
			if err := o.lim.Wait(ctx); err != nil {
				return res, fmt.Errorf("orchestrator: rate limit (scan): %w", err)
			}
			findings, err := eng.Scan(ctx, target, req.Program, runID)
			if err != nil {
				// One engine failing on one target does NOT abort the run: record it
				// and carry on so the other engines/targets still produce and save
				// findings. Only a cancelled context is fatal.
				if ctx.Err() != nil {
					return res, fmt.Errorf("orchestrator: cancelled: %w", ctx.Err())
				}
				res.EngineErrors = append(res.EngineErrors, EngineError{Engine: eng.Name(), Target: target, Err: req.AuthHeaders.Scrub(err.Error())})
				continue
			}
			for _, f := range findings {
				// Last guard: an out-of-scope finding is not saved. This judges a result,
				// not a connection, so it is recorded separately from egress denials.
				dd := o.guard.Evaluate(f.Location.URL)
				if !dd.Allowed {
					eev := o.auditEvent(req.Program, runID, dd, LayerFinding)
					o.audit(eev)
					res.Denied = append(res.Denied, eev)
					continue
				}
				// Lever 1: remove auth header values from the evidence before saving.
				// Session credentials must not be stored in findings/reports (Principle #5).
				if len(authNames) > 0 && f.Evidence != nil {
					f.Evidence.RedactHeaders(authNames)
				}
				sr, err := o.store.Save(ctx, f)
				if err != nil {
					return res, fmt.Errorf("orchestrator: cannot save finding: %w", err)
				}
				if sr.Deduplicated {
					res.Duplicates++
				} else {
					res.FindingsSaved++
				}
			}
		}
	}
	egressMu.Lock()
	res.Denied = append(res.Denied, egressDenied...)
	egressMu.Unlock()
	return res, nil
}

func (o *Orchestrator) needsEgressProxy() bool {
	for _, e := range o.engines {
		if _, ok := e.(engine.ProxyAware); ok {
			return true
		}
	}
	if _, ok := o.recon.(engine.ProxyAware); ok {
		return true
	}
	return false
}

func (o *Orchestrator) auditEvent(program, runID string, d scope.Result, layer Layer) AuditEvent {
	return AuditEvent{
		Time:         o.now().UTC(),
		Program:      program,
		RunID:        runID,
		Target:       d.Target,
		Allowed:      d.Allowed,
		Reason:       d.Reason,
		Layer:        layer,
		MatchedEntry: d.MatchedEntry,
	}
}
