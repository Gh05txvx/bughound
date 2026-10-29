package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"bughound/internal/payload"
)

// CatalogStore mempersist Bank Payload (BH-SPEC-PAYLOAD): katalog metadata
// seragam di atas template native. Katalog diturunkan dari sumber (lihat
// internal/payload) lalu disimpan agar UI bisa menampilkan & memfilter daftar
// tanpa men-scan ulang ribuan berkas tiap muat halaman. Refresh mengganti
// seluruh katalog secara atomik.
//
// Interface terpisah (bukan bagian Store) agar implementasi store lama tetap
// kompatibel; pemanggil mendeteksinya lewat type assertion, seperti UserStore.
type CatalogStore interface {
	// ReplaceCatalog mengganti seluruh katalog dengan snapshot baru (atomik).
	ReplaceCatalog(ctx context.Context, cat payload.Catalog) error
	// ListCatalog mengembalikan entri terfilter (diurut severity lalu id) plus
	// total entri yang cocok filter (untuk paginasi).
	ListCatalog(ctx context.Context, q CatalogQuery) ([]payload.Entry, int, error)
	// CatalogStats mengembalikan agregat untuk ringkasan (tanpa filter).
	CatalogStats(ctx context.Context) (CatalogStats, error)
	// ListCatalogSources mengembalikan ringkasan tiap sumber.
	ListCatalogSources(ctx context.Context) ([]payload.SourceInfo, error)
}

// CatalogQuery memfilter daftar entri katalog.
type CatalogQuery struct {
	Search   string // cocok template_id ATAU name (substring, case-insensitive)
	Engine   string
	Trust    string
	Severity string
	Tag      string
	Enabled  string // "" = semua, "1" = aktif, "0" = nonaktif
	Limit    int    // 0 = tanpa batas
	Offset   int
}

// CatalogStats meringkas katalog untuk kartu ringkasan di UI.
type CatalogStats struct {
	Total      int
	Enabled    int
	ByEngine   map[string]int
	ByTrust    map[string]int
	BySeverity map[string]int
	BuiltAt    time.Time
}

// catalogSevRank: ekspresi SQL untuk urut severity terberat dulu.
const catalogSevRank = `CASE severity
	WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3
	WHEN 'low' THEN 2 WHEN 'info' THEN 1 ELSE 0 END`

// ---- SQLite ----

// ReplaceCatalog: lihat CatalogStore.
func (s *SQLite) ReplaceCatalog(ctx context.Context, cat payload.Catalog) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: mulai transaksi katalog: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op bila sudah Commit

	for _, q := range []string{`DELETE FROM catalog`, `DELETE FROM catalog_sources`} {
		if _, err := tx.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("store: kosongkan katalog: %w", err)
		}
	}

	ins, err := tx.PrepareContext(ctx,
		`INSERT INTO catalog (template_id,source,engine,trust,severity,type,tags,name,enabled,version,doc)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(template_id) DO NOTHING`)
	if err != nil {
		return fmt.Errorf("store: siapkan insert katalog: %w", err)
	}
	defer ins.Close()

	for i := range cat.Entries {
		e := &cat.Entries[i]
		doc, err := json.Marshal(e)
		if err != nil {
			return fmt.Errorf("store: marshal entri katalog: %w", err)
		}
		enabled := 0
		if e.Enabled {
			enabled = 1
		}
		if _, err := ins.ExecContext(ctx,
			e.TemplateID, e.Source, e.Engine, string(e.Trust), string(e.SeverityDefault),
			e.Type, " "+strings.Join(e.Tags, " ")+" ", e.Name, enabled, e.Version, string(doc),
		); err != nil {
			return fmt.Errorf("store: simpan entri katalog: %w", err)
		}
	}

	for _, src := range cat.Sources {
		doc, err := json.Marshal(src)
		if err != nil {
			return fmt.Errorf("store: marshal sumber katalog: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO catalog_sources (id,doc,updated_at) VALUES (?,?,?)
			 ON CONFLICT(id) DO UPDATE SET doc=excluded.doc, updated_at=excluded.updated_at`,
			src.ID, string(doc), src.UpdatedAt.UTC().Format(time.RFC3339),
		); err != nil {
			return fmt.Errorf("store: simpan sumber katalog: %w", err)
		}
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO catalog_meta (k,v) VALUES ('built_at',?)
		 ON CONFLICT(k) DO UPDATE SET v=excluded.v`,
		cat.BuiltAt.UTC().Format(time.RFC3339),
	); err != nil {
		return fmt.Errorf("store: simpan meta katalog: %w", err)
	}
	return tx.Commit()
}

func catalogWhere(q CatalogQuery) (string, []any) {
	var where []string
	var args []any
	if s := strings.TrimSpace(q.Search); s != "" {
		where = append(where, "(LOWER(template_id) LIKE ? OR LOWER(name) LIKE ?)")
		pat := "%" + strings.ToLower(s) + "%"
		args = append(args, pat, pat)
	}
	if q.Engine != "" {
		where = append(where, "engine=?")
		args = append(args, q.Engine)
	}
	if q.Trust != "" {
		where = append(where, "trust=?")
		args = append(args, q.Trust)
	}
	if q.Severity != "" {
		where = append(where, "severity=?")
		args = append(args, q.Severity)
	}
	if t := strings.TrimSpace(q.Tag); t != "" {
		where = append(where, "tags LIKE ?")
		args = append(args, "% "+t+" %")
	}
	switch q.Enabled {
	case "1":
		where = append(where, "enabled=1")
	case "0":
		where = append(where, "enabled=0")
	}
	if len(where) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(where, " AND "), args
}

// ListCatalog: lihat CatalogStore.
func (s *SQLite) ListCatalog(ctx context.Context, q CatalogQuery) ([]payload.Entry, int, error) {
	whereSQL, args := catalogWhere(q)

	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM catalog`+whereSQL, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("store: hitung katalog: %w", err)
	}

	query := `SELECT doc FROM catalog` + whereSQL + ` ORDER BY ` + catalogSevRank + ` DESC, template_id ASC`
	if q.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d OFFSET %d", q.Limit, q.Offset)
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("store: query katalog: %w", err)
	}
	defer rows.Close()
	var out []payload.Entry
	for rows.Next() {
		var doc string
		if err := rows.Scan(&doc); err != nil {
			return nil, 0, err
		}
		var e payload.Entry
		if err := json.Unmarshal([]byte(doc), &e); err != nil {
			return nil, 0, fmt.Errorf("store: entri katalog rusak: %w", err)
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// CatalogStats: lihat CatalogStore.
func (s *SQLite) CatalogStats(ctx context.Context) (CatalogStats, error) {
	st := CatalogStats{ByEngine: map[string]int{}, ByTrust: map[string]int{}, BySeverity: map[string]int{}}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(enabled),0) FROM catalog`).Scan(&st.Total, &st.Enabled); err != nil {
		return st, fmt.Errorf("store: statistik katalog: %w", err)
	}
	group := func(col string, dst map[string]int) error {
		rows, err := s.db.QueryContext(ctx, `SELECT `+col+`, COUNT(*) FROM catalog GROUP BY `+col)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var k string
			var n int
			if err := rows.Scan(&k, &n); err != nil {
				return err
			}
			if k == "" {
				k = "-"
			}
			dst[k] = n
		}
		return rows.Err()
	}
	for col, dst := range map[string]map[string]int{"engine": st.ByEngine, "trust": st.ByTrust, "severity": st.BySeverity} {
		if err := group(col, dst); err != nil {
			return st, fmt.Errorf("store: statistik katalog (%s): %w", col, err)
		}
	}
	var builtAt string
	if err := s.db.QueryRowContext(ctx, `SELECT v FROM catalog_meta WHERE k='built_at'`).Scan(&builtAt); err != nil && err != sql.ErrNoRows {
		return st, fmt.Errorf("store: meta katalog: %w", err)
	}
	st.BuiltAt, _ = time.Parse(time.RFC3339, builtAt)
	return st, nil
}

// ListCatalogSources: lihat CatalogStore.
func (s *SQLite) ListCatalogSources(ctx context.Context) ([]payload.SourceInfo, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT doc FROM catalog_sources ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("store: daftar sumber katalog: %w", err)
	}
	defer rows.Close()
	var out []payload.SourceInfo
	for rows.Next() {
		var doc string
		if err := rows.Scan(&doc); err != nil {
			return nil, err
		}
		var si payload.SourceInfo
		if err := json.Unmarshal([]byte(doc), &si); err != nil {
			return nil, fmt.Errorf("store: sumber katalog rusak: %w", err)
		}
		out = append(out, si)
	}
	return out, rows.Err()
}

// ---- Mem ----

// ReplaceCatalog: lihat CatalogStore.
func (m *Mem) ReplaceCatalog(ctx context.Context, cat payload.Catalog) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.catalog = append([]payload.Entry(nil), cat.Entries...)
	m.catalogSources = append([]payload.SourceInfo(nil), cat.Sources...)
	m.catalogBuiltAt = cat.BuiltAt
	return nil
}

func catalogMatch(e payload.Entry, q CatalogQuery) bool {
	if s := strings.ToLower(strings.TrimSpace(q.Search)); s != "" {
		if !strings.Contains(strings.ToLower(e.TemplateID), s) && !strings.Contains(strings.ToLower(e.Name), s) {
			return false
		}
	}
	if q.Engine != "" && e.Engine != q.Engine {
		return false
	}
	if q.Trust != "" && string(e.Trust) != q.Trust {
		return false
	}
	if q.Severity != "" && string(e.SeverityDefault) != q.Severity {
		return false
	}
	if t := strings.TrimSpace(q.Tag); t != "" && !containsString(e.Tags, t) {
		return false
	}
	switch q.Enabled {
	case "1":
		if !e.Enabled {
			return false
		}
	case "0":
		if e.Enabled {
			return false
		}
	}
	return true
}

// ListCatalog: lihat CatalogStore.
func (m *Mem) ListCatalog(ctx context.Context, q CatalogQuery) ([]payload.Entry, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var matched []payload.Entry
	for _, e := range m.catalog {
		if catalogMatch(e, q) {
			matched = append(matched, e)
		}
	}
	sort.SliceStable(matched, func(i, j int) bool {
		ri, rj := severityRank(matched[i].SeverityDefault), severityRank(matched[j].SeverityDefault)
		if ri != rj {
			return ri > rj
		}
		return matched[i].TemplateID < matched[j].TemplateID
	})
	total := len(matched)
	if q.Offset > 0 {
		if q.Offset >= len(matched) {
			return nil, total, nil
		}
		matched = matched[q.Offset:]
	}
	if q.Limit > 0 && len(matched) > q.Limit {
		matched = matched[:q.Limit]
	}
	return matched, total, nil
}

// CatalogStats: lihat CatalogStore.
func (m *Mem) CatalogStats(ctx context.Context) (CatalogStats, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	st := CatalogStats{ByEngine: map[string]int{}, ByTrust: map[string]int{}, BySeverity: map[string]int{}, BuiltAt: m.catalogBuiltAt}
	for _, e := range m.catalog {
		st.Total++
		if e.Enabled {
			st.Enabled++
		}
		st.ByEngine[e.Engine]++
		st.ByTrust[string(e.Trust)]++
		sev := string(e.SeverityDefault)
		if sev == "" {
			sev = "-"
		}
		st.BySeverity[sev]++
	}
	return st, nil
}

// ListCatalogSources: lihat CatalogStore.
func (m *Mem) ListCatalogSources(ctx context.Context) ([]payload.SourceInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]payload.SourceInfo(nil), m.catalogSources...), nil
}
