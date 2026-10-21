// Package orchestrator menyatukan scope guard, engine, dan store menjadi satu
// alur scan. Scope guard adalah SATU-SATUNYA titik keputusan dan ditegakkan di
// dua lapis (BH-SPEC-SCOPE): saat input/perencanaan dan saat egress (sebelum
// temuan dari engine diterima). Tidak ada jalur sampingan.
package orchestrator

import (
	"context"
	"fmt"
	"time"

	"bughound/internal/engine"
	"bughound/internal/scope"
	"bughound/internal/store"
)

// Layer menandai lapis penegakan scope.
type Layer string

const (
	LayerInput  Layer = "input"  // saat perencanaan, sebelum masuk antrean scan
	LayerEgress Layer = "egress" // saat temuan/koneksi keluar hendak diterima
)

// AuditEvent adalah satu entri audit trail untuk keputusan scope. Dikirim ke
// sink audit baik untuk izin maupun tolak (BH-SPEC-SCOPE: keputusan tercatat).
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
	audit  func(AuditEvent)
	now    func() time.Time
}

// New membuat Orchestrator. audit boleh nil (jadi no-op).
func New(guard *scope.Guard, eng engine.Engine, st store.Store, audit func(AuditEvent)) *Orchestrator {
	if audit == nil {
		audit = func(AuditEvent) {}
	}
	return &Orchestrator{guard: guard, engine: eng, store: st, audit: audit, now: time.Now}
}

// ScanRequest meminta scan satu program terhadap sekumpulan target.
type ScanRequest struct {
	Program string
	RunID   string // dibuat otomatis bila kosong
	Targets []string
}

// ScanResult meringkas hasil satu run.
type ScanResult struct {
	RunID         string
	Scanned       []string     // target in-scope yang discan (ternormalkan)
	Denied        []AuditEvent // target/temuan yang ditolak guard (input/egress)
	FindingsSaved int
	Duplicates    int
}

// RunScan menegakkan scope guard, menjalankan engine untuk target in-scope,
// memeriksa ulang setiap temuan di lapis egress, lalu menyimpan yang lolos.
func (o *Orchestrator) RunScan(ctx context.Context, req ScanRequest) (ScanResult, error) {
	if req.Program == "" {
		return ScanResult{}, fmt.Errorf("orchestrator: program wajib")
	}
	runID := req.RunID
	if runID == "" {
		runID = "run_" + o.now().UTC().Format("20060102_150405")
	}
	res := ScanResult{RunID: runID}

	for _, target := range req.Targets {
		// Lapis 1 — penegakan saat input/perencanaan.
		d := o.guard.Evaluate(target)
		ev := o.auditEvent(req.Program, runID, d, LayerInput)
		o.audit(ev)
		if !d.Allowed {
			res.Denied = append(res.Denied, ev)
			continue
		}
		res.Scanned = append(res.Scanned, d.Target)

		findings, err := o.engine.Scan(ctx, target, req.Program, runID)
		if err != nil {
			return res, fmt.Errorf("orchestrator: engine %s gagal scan %q: %w", o.engine.Name(), target, err)
		}

		for _, f := range findings {
			// Lapis 2 — penegakan egress. Temuan pada lokasi di luar scope
			// (mis. akibat redirect/link baru) dihadang walau target awal in-scope.
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
