// Package orchestrator menyatukan scope guard, (opsional) recon, engine DAST,
// rate limiter, dan store menjadi satu alur scan.
//
// Dua jaminan struktural (BH-SPEC-SCOPE + prinsip bughound):
//   - Scope guard adalah SATU-SATUNYA titik keputusan, ditegakkan dua lapis:
//     saat input/perencanaan dan saat egress (sebelum temuan diterima). Aset
//     hasil recon pun wajib lolos scope guard; recon tidak memintas scope.
//   - Rate limiter ADA DI JALUR EKSEKUSI: setiap pemanggilan recon dan setiap
//     scan menunggu token lebih dulu, dan limiter tidak bisa dimatikan.
package orchestrator

import (
	"context"
	"fmt"
	"time"

	"bughound/internal/engine"
	"bughound/internal/ratelimit"
	"bughound/internal/recon"
	"bughound/internal/scope"
	"bughound/internal/store"
)

// Layer menandai lapis penegakan scope.
type Layer string

const (
	LayerInput  Layer = "input"  // saat perencanaan, sebelum masuk antrean scan
	LayerEgress Layer = "egress" // saat temuan/koneksi keluar hendak diterima
)

// AuditEvent adalah satu entri audit trail untuk keputusan scope.
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

// Orchestrator menjalankan scan untuk satu program.
type Orchestrator struct {
	guard  *scope.Guard
	engine engine.Engine
	store  store.Store
	lim    *ratelimit.Limiter
	recon  recon.Engine // opsional
	audit  func(AuditEvent)
	now    func() time.Time
}

// New membuat Orchestrator. audit boleh nil (jadi no-op). lim boleh nil, tetapi
// TIDAK dimatikan: nil diganti limiter default yang aman (rate limiter selalu
// ada di jalur eksekusi).
func New(guard *scope.Guard, eng engine.Engine, st store.Store, lim *ratelimit.Limiter, audit func(AuditEvent)) *Orchestrator {
	if audit == nil {
		audit = func(AuditEvent) {}
	}
	if lim == nil {
		lim = ratelimit.New(ratelimit.Config{})
	}
	return &Orchestrator{guard: guard, engine: eng, store: st, lim: lim, audit: audit, now: time.Now}
}

// UseRecon mengaktifkan tahap recon (opsional).
func (o *Orchestrator) UseRecon(r recon.Engine) { o.recon = r }

// ScanRequest meminta scan satu program.
type ScanRequest struct {
	Program string
	RunID   string   // dibuat otomatis bila kosong
	Seeds   []string // domain awal untuk recon (opsional)
	Targets []string // target eksplisit
}

// ScanResult meringkas hasil satu run.
type ScanResult struct {
	RunID         string
	Discovered    int          // aset dari recon
	Scanned       []string     // target in-scope yang discan (ternormalkan)
	Denied        []AuditEvent // target/temuan yang ditolak guard (input/egress)
	FindingsSaved int
	Duplicates    int
}

// RunScan menjalankan recon (bila aktif), menegakkan scope guard + rate limiter,
// menjalankan engine untuk target in-scope, memeriksa ulang setiap temuan di
// lapis egress, lalu menyimpan yang lolos.
func (o *Orchestrator) RunScan(ctx context.Context, req ScanRequest) (ScanResult, error) {
	if req.Program == "" {
		return ScanResult{}, fmt.Errorf("orchestrator: program wajib")
	}
	runID := req.RunID
	if runID == "" {
		runID = "run_" + o.now().UTC().Format("20060102_150405")
	}
	res := ScanResult{RunID: runID}

	candidates := append([]string{}, req.Targets...)

	// Tahap recon (opsional). Pemanggilannya pun dibatasi rate limiter.
	if o.recon != nil && len(req.Seeds) > 0 {
		if err := o.lim.Wait(ctx); err != nil {
			return res, fmt.Errorf("orchestrator: rate limit (recon): %w", err)
		}
		assets, err := o.recon.Discover(ctx, req.Seeds)
		if err != nil {
			return res, fmt.Errorf("orchestrator: recon %s gagal: %w", o.recon.Name(), err)
		}
		for _, a := range assets {
			res.Discovered++
			candidates = append(candidates, a.Value)
		}
	}

	// Tahap DAST atas kandidat in-scope.
	seen := map[string]bool{}
	for _, target := range candidates {
		if target == "" || seen[target] {
			continue
		}
		seen[target] = true

		// Lapis 1 — penegakan saat input/perencanaan.
		d := o.guard.Evaluate(target)
		ev := o.auditEvent(req.Program, runID, d, LayerInput)
		o.audit(ev)
		if !d.Allowed {
			res.Denied = append(res.Denied, ev)
			continue
		}
		res.Scanned = append(res.Scanned, d.Target)

		// Rate limiter di jalur eksekusi: tunggu token sebelum menjalankan engine.
		if err := o.lim.Wait(ctx); err != nil {
			return res, fmt.Errorf("orchestrator: rate limit (scan): %w", err)
		}
		findings, err := o.engine.Scan(ctx, target, req.Program, runID)
		if err != nil {
			return res, fmt.Errorf("orchestrator: engine %s gagal scan %q: %w", o.engine.Name(), target, err)
		}

		for _, f := range findings {
			// Lapis 2 — penegakan egress.
			dd := o.guard.Evaluate(f.Location.URL)
			if !dd.Allowed {
				eev := o.auditEvent(req.Program, runID, dd, LayerEgress)
				o.audit(eev)
				res.Denied = append(res.Denied, eev)
				continue
			}
			sr, err := o.store.Save(ctx, f)
			if err != nil {
				return res, fmt.Errorf("orchestrator: gagal simpan temuan: %w", err)
			}
			if sr.Deduplicated {
				res.Duplicates++
			} else {
				res.FindingsSaved++
			}
		}
	}
	return res, nil
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
