package store

// Persistensi riwayat run scan (jobs.Run) agar panel Proses & detail run selamat
// dari restart/redeploy. *SQLite dan *Mem mengimplementasikan jobs.Store; web
// memasang persistensi queue lewat type assertion (degradasi mulus bila store tak
// mendukung), sama seperti CatalogStore/AIStore. Run disimpan utuh sebagai doc
// JSON (pola findings), dengan kolom terindeks (program, enqueued_at) untuk list
// terurut. Tak ada rahasia di sini — hanya metadata & ringkasan hasil scan.

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"bughound/internal/jobs"
)

// ---- SQLite ----

func (s *SQLite) LoadRuns(ctx context.Context) ([]*jobs.Run, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT doc FROM runs ORDER BY enqueued_at ASC, id ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: muat run: %w", err)
	}
	defer rows.Close()
	var out []*jobs.Run
	for rows.Next() {
		var doc string
		if err := rows.Scan(&doc); err != nil {
			return nil, fmt.Errorf("store: baca run: %w", err)
		}
		var r jobs.Run
		if err := json.Unmarshal([]byte(doc), &r); err != nil {
			return nil, fmt.Errorf("store: decode run: %w", err)
		}
		out = append(out, &r)
	}
	return out, rows.Err()
}

func (s *SQLite) SaveRun(ctx context.Context, r *jobs.Run) error {
	doc, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("store: encode run: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO runs (id, program, status, label, enqueued_at, started_at, finished_at, doc)
		 VALUES (?,?,?,?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET
		   program=excluded.program, status=excluded.status, label=excluded.label,
		   enqueued_at=excluded.enqueued_at, started_at=excluded.started_at,
		   finished_at=excluded.finished_at, doc=excluded.doc`,
		r.ID, r.Program, string(r.Status), r.Label,
		runTime(r.EnqueuedAt), runTime(r.StartedAt), runTime(r.FinishedAt), string(doc))
	if err != nil {
		return fmt.Errorf("store: simpan run: %w", err)
	}
	return nil
}

func (s *SQLite) DeleteRun(ctx context.Context, id string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM runs WHERE id=?`, id); err != nil {
		return fmt.Errorf("store: hapus run: %w", err)
	}
	return nil
}

// runTime memformat waktu ke RFC3339 UTC; zero → "" (kolom tak terisi). Nilai
// kolom hanya untuk urutan/filter — kebenaran penuh ada di doc JSON.
func runTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// ---- Mem ----

func (m *Mem) LoadRuns(ctx context.Context) ([]*jobs.Run, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*jobs.Run, 0, len(m.runs))
	for _, r := range m.runs {
		c := *r
		out = append(out, &c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].EnqueuedAt.Equal(out[j].EnqueuedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].EnqueuedAt.Before(out[j].EnqueuedAt)
	})
	return out, nil
}

func (m *Mem) SaveRun(ctx context.Context, r *jobs.Run) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.runs == nil {
		m.runs = map[string]*jobs.Run{}
	}
	c := *r
	m.runs[r.ID] = &c
	return nil
}

func (m *Mem) DeleteRun(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.runs, id)
	return nil
}
