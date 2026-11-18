// Package sast adds static analysis (SAST) to bughound as a PLUGIN behind the
// uniform engine contract: each adapter normalizes its results into the Uniform
// Finding Schema (BH-SPEC-FINDING), just like the DAST engines.
//
// The important difference from DAST: SAST reads LOCAL CODE, not URLs. So the
// "mandatory boundary" (principles #1 and #2) takes the form of a PATH SCOPE
// here: analysis may only run inside one allowed root (default deny; path
// traversal and escapes through symlinks are denied). There are no network
// connections, so neither egress/URL scope nor the rate limiter applies.
package sast

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"bughound/internal/audit"
	"bughound/internal/finding"
	"bughound/internal/store"
)

// ErrDisabled is returned when SAST is not configured (empty root).
var ErrDisabled = errors.New("sast: disabled (set -sast-root)")

// ErrOutOfScope is returned when the requested path leaves the root.
var ErrOutOfScope = errors.New("sast: path is outside the allowed root (denied)")

// Engine is one SAST adapter. Analyze analyzes the directory dir (already
// validated as in scope) and returns normalized findings. The adapter fills in
// the semantic fields (type/title/severity/location/evidence/...); the store
// sets id/dedup_key/schema_version/created_at.
type Engine interface {
	Name() string
	Analyze(ctx context.Context, dir, program, runID string) ([]*finding.Finding, error)
}

// Factory creates an Engine instance (used by the plugin registry).
type Factory func() Engine

var (
	regMu    sync.RWMutex
	registry = map[string]Factory{}
)

// Register registers a SAST adapter under a unique name (called from init()).
// Registering the same name twice replaces the old one.
func Register(name string, f Factory) {
	regMu.Lock()
	defer regMu.Unlock()
	registry[name] = f
}

// Names returns the registered adapter names, sorted.
func Names() []string {
	regMu.RLock()
	defer regMu.RUnlock()
	out := make([]string, 0, len(registry))
	for n := range registry {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Lookup creates the registered engine called name.
func Lookup(name string) (Engine, bool) {
	regMu.RLock()
	f, ok := registry[name]
	regMu.RUnlock()
	if !ok {
		return nil, false
	}
	return f(), true
}

// Resolve enforces the PATH SCOPE: it returns the absolute path of sub inside
// root, or an error. An empty root -> ErrDisabled. A path that leaves the root
// (including through ".." or a symlink) -> ErrOutOfScope. The path must exist.
func Resolve(root, sub string) (string, error) {
	if strings.TrimSpace(root) == "" {
		return "", ErrDisabled
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("sast: root: %w", err)
	}
	if real, err := filepath.EvalSymlinks(absRoot); err == nil {
		absRoot = real
	}
	// filepath.Join cleans "..", but the result can still leave the root; Rel checks that.
	target := filepath.Join(absRoot, sub)
	real, err := filepath.EvalSymlinks(target)
	if err != nil {
		return "", fmt.Errorf("sast: path: %w", err)
	}
	target = real
	rel, err := filepath.Rel(absRoot, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", ErrOutOfScope
	}
	if _, err := os.Stat(target); err != nil {
		return "", fmt.Errorf("sast: path: %w", err)
	}
	return target, nil
}

// Result summarizes one SAST run.
type Result struct {
	Saved      int
	Duplicates int
	ByEngine   map[string]int // engine name -> raw finding count
}

// Run runs each engine on dir (already validated by Resolve), saves the
// findings (the store dedups them) and records the audit. It does not touch
// the network.
func Run(ctx context.Context, dir, srcLabel, program, runID string, engines []Engine, st store.Store, al audit.Log) (Result, error) {
	res := Result{ByEngine: map[string]int{}}
	if len(engines) == 0 {
		return res, errors.New("sast: no engines")
	}
	// An empty subpath = the whole root (see the UI's "empty = whole root"); label
	// it "." so the required `target` field of a finding is never empty, since the
	// store rejects an empty target (BH-SPEC-FINDING).
	if strings.TrimSpace(srcLabel) == "" {
		srcLabel = "."
	}
	if al != nil {
		_, _ = al.Append(ctx, audit.Event{Kind: "sast.start", Program: program, RunID: runID, Target: srcLabel, Message: "root: " + dir})
	}
	for _, eng := range engines {
		fs, err := eng.Analyze(ctx, dir, program, runID)
		if err != nil {
			if al != nil {
				_, _ = al.Append(ctx, audit.Event{Kind: "sast.error", Program: program, RunID: runID, Target: srcLabel, Message: eng.Name() + ": " + err.Error()})
			}
			return res, fmt.Errorf("sast: %s: %w", eng.Name(), err)
		}
		res.ByEngine[eng.Name()] += len(fs)
		for _, f := range fs {
			f.Program = program
			f.RunID = runID
			if f.Target == "" {
				f.Target = srcLabel
			}
			sr, serr := st.Save(ctx, f)
			if serr != nil {
				return res, fmt.Errorf("sast: save: %w", serr)
			}
			if sr.Deduplicated {
				res.Duplicates++
			} else {
				res.Saved++
			}
		}
	}
	if al != nil {
		_, _ = al.Append(ctx, audit.Event{
			Kind: "sast.finish", Program: program, RunID: runID, Target: srcLabel,
			Message: fmt.Sprintf("%d new findings, %d duplicates", res.Saved, res.Duplicates),
		})
	}
	return res, nil
}
