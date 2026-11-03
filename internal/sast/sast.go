// Package sast menambahkan analisis statis (SAST) ke bughound sebagai PLUGIN
// di balik kontrak engine seragam: tiap adapter menormalkan hasilnya ke Skema
// Temuan Seragam (BH-SPEC-FINDING), sama seperti engine DAST.
//
// Perbedaan penting dari DAST: SAST membaca KODE LOKAL, bukan URL. Maka
// "boundary wajib" (prinsip #1 & #2) di sini berbentuk PATH SCOPE: analisis
// hanya boleh di dalam satu root yang diizinkan (default-deny; path traversal
// & escape via symlink ditolak). Tidak ada koneksi jaringan, jadi tak ada
// egress/scope-URL maupun rate limiter yang relevan.
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

// ErrDisabled dikembalikan bila SAST tak dikonfigurasi (root kosong).
var ErrDisabled = errors.New("sast: dinonaktifkan (set -sast-root)")

// ErrOutOfScope dikembalikan bila path yang diminta keluar dari root.
var ErrOutOfScope = errors.New("sast: path di luar root yang diizinkan (ditolak)")

// Engine adalah satu adapter SAST. Analyze menganalisis direktori dir (sudah
// divalidasi in-scope) dan mengembalikan temuan ternormalkan. Adapter mengisi
// field semantik (type/title/severity/location/evidence/...); store menetapkan
// id/dedup_key/schema_version/created_at.
type Engine interface {
	Name() string
	Analyze(ctx context.Context, dir, program, runID string) ([]*finding.Finding, error)
}

// Factory membuat instance Engine (dipakai registry plugin).
type Factory func() Engine

var (
	regMu    sync.RWMutex
	registry = map[string]Factory{}
)

// Register mendaftarkan adapter SAST dengan nama unik (dipanggil dari init()).
// Pendaftaran ganda untuk nama yang sama menimpa yang lama.
func Register(name string, f Factory) {
	regMu.Lock()
	defer regMu.Unlock()
	registry[name] = f
}

// Names mengembalikan nama adapter terdaftar, terurut.
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

// Lookup membuat engine terdaftar bernama name.
func Lookup(name string) (Engine, bool) {
	regMu.RLock()
	f, ok := registry[name]
	regMu.RUnlock()
	if !ok {
		return nil, false
	}
	return f(), true
}

// Resolve menegakkan PATH SCOPE: mengembalikan path absolut sub di dalam root,
// atau error. root kosong -> ErrDisabled. Path yang keluar dari root (termasuk
// lewat ".." atau symlink) -> ErrOutOfScope. Path harus ada.
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
	// filepath.Join membersihkan "..", tapi tetap bisa keluar root; dicek via Rel.
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

// Result meringkas satu run SAST.
type Result struct {
	Saved      int
	Duplicates int
	ByEngine   map[string]int // nama engine -> jumlah temuan mentah
}

// Run menjalankan tiap engine pada dir (sudah divalidasi Resolve), menyimpan
// temuan (dedup oleh store), dan mencatat audit. Tidak menyentuh jaringan.
func Run(ctx context.Context, dir, srcLabel, program, runID string, engines []Engine, st store.Store, al audit.Log) (Result, error) {
	res := Result{ByEngine: map[string]int{}}
	if len(engines) == 0 {
		return res, errors.New("sast: tak ada engine")
	}
	// Subpath kosong = seluruh root (lihat UI "kosong = seluruh root"); beri
	// label "." agar field wajib `target` pada temuan tak pernah kosong —
	// store menolak target kosong (BH-SPEC-FINDING).
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
				return res, fmt.Errorf("sast: simpan: %w", serr)
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
			Message: fmt.Sprintf("%d temuan baru, %d duplikat", res.Saved, res.Duplicates),
		})
	}
	return res, nil
}
