package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"bughound/internal/finding"

	_ "modernc.org/sqlite" // the "sqlite" driver (pure Go, no cgo => still a single binary)
)

// SQLite is a Store backed by SQLite. Findings are stored whole as JSON
// documents (the schema is versioned in the JSON), with indexed columns for
// triage queries. Dedup is enforced the same way as in Mem: per (program,
// dedup_key).
type SQLite struct {
	db  *sql.DB
	now func() time.Time
	mu  sync.Mutex // keeps the dedup decision atomic (check + write)
}

// OpenSQLite opens/creates the database at path (or ":memory:").
func OpenSQLite(path string) (*SQLite, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("store: open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1) // avoids "database is locked"
	s := &SQLite{db: db, now: time.Now}
	if err := s.init(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *SQLite) init() error {
	stmts := []string{
		`PRAGMA journal_mode=WAL;`,
		`PRAGMA busy_timeout=5000;`,
		`CREATE TABLE IF NOT EXISTS findings (
			id            TEXT PRIMARY KEY,
			program       TEXT NOT NULL,
			run_id        TEXT NOT NULL,
			dedup_key     TEXT NOT NULL,
			type          TEXT NOT NULL,
			target        TEXT NOT NULL,
			severity      TEXT NOT NULL,
			status        TEXT NOT NULL,
			duplicate_of  TEXT,
			created_at    TEXT NOT NULL,
			doc           TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_findings_program ON findings(program);`,
		`CREATE INDEX IF NOT EXISTS idx_findings_dedup   ON findings(program, dedup_key);`,
		`CREATE TABLE IF NOT EXISTS programs (
			name       TEXT PRIMARY KEY,
			in_scope   TEXT NOT NULL,
			out_scope  TEXT NOT NULL,
			preset     TEXT NOT NULL DEFAULT '{}',
			updated_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS users (
			username   TEXT PRIMARY KEY,
			role       TEXT NOT NULL,
			pass_hash  TEXT NOT NULL,
			created_at TEXT NOT NULL
		);`,
		// Payload Bank (BH-SPEC-PAYLOAD): a metadata catalog on top of the native
		// templates. The whole entry is stored as a JSON doc; indexed columns serve the
		// UI filters.
		`CREATE TABLE IF NOT EXISTS catalog (
			template_id TEXT PRIMARY KEY,
			source      TEXT NOT NULL,
			engine      TEXT NOT NULL,
			trust       TEXT NOT NULL,
			severity    TEXT,
			type        TEXT,
			tags        TEXT,
			name        TEXT NOT NULL,
			enabled     INTEGER NOT NULL,
			version     TEXT NOT NULL,
			doc         TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_catalog_engine ON catalog(engine);`,
		`CREATE INDEX IF NOT EXISTS idx_catalog_trust  ON catalog(trust);`,
		`CREATE INDEX IF NOT EXISTS idx_catalog_sev    ON catalog(severity);`,
		`CREATE TABLE IF NOT EXISTS catalog_sources (
			id         TEXT PRIMARY KEY,
			doc        TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS catalog_meta (
			k TEXT PRIMARY KEY,
			v TEXT NOT NULL
		);`,
		// AI what-if analysis cache per finding (BH analyst/MCP in the web UI). Only the
		// part the LLM reasons out is stored; it is dropped/regenerated when
		// source_hash is stale. The secret (the API key) is NOT here; it lives in the
		// encrypted vault.
		`CREATE TABLE IF NOT EXISTS ai_analysis (
			finding_id  TEXT PRIMARY KEY,
			program     TEXT NOT NULL,
			model       TEXT NOT NULL,
			source_hash TEXT NOT NULL,
			payload     TEXT NOT NULL,
			created_at  TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_ai_program ON ai_analysis(program);`,
		// Non-secret app settings (e.g. the Claude model chosen for AI analysis).
		`CREATE TABLE IF NOT EXISTS app_settings (
			k TEXT PRIMARY KEY,
			v TEXT NOT NULL
		);`,
		// Scan run history (jobs.Run) so the Processes panel and the run details
		// survive a restart/redeploy. The whole run is in a JSON doc; indexed columns
		// serve the sorted list.
		`CREATE TABLE IF NOT EXISTS runs (
			id          TEXT PRIMARY KEY,
			program     TEXT NOT NULL,
			status      TEXT NOT NULL,
			label       TEXT,
			enqueued_at TEXT NOT NULL,
			started_at  TEXT,
			finished_at TEXT,
			doc         TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_runs_program ON runs(program);`,
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("store: init schema: %w", err)
		}
	}
	// Additive migration: a DB created before the `preset` column existed does not
	// have it (CREATE TABLE IF NOT EXISTS does not change an old table). ADD COLUMN
	// fails when the column already exists, so check through PRAGMA first. Safe and
	// idempotent.
	if ok, err := s.hasColumn("programs", "preset"); err != nil {
		return err
	} else if !ok {
		if _, err := s.db.Exec(`ALTER TABLE programs ADD COLUMN preset TEXT NOT NULL DEFAULT '{}'`); err != nil {
			return fmt.Errorf("store: migrate the preset column: %w", err)
		}
	}
	return nil
}

// hasColumn reports whether table has a column named col. table is an internal
// constant (not user input), so it is safe to format into the PRAGMA.
func (s *SQLite) hasColumn(table, col string) (bool, error) {
	rows, err := s.db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return false, fmt.Errorf("store: check column %s.%s: %w", table, col, err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cid, notnull, pk int
			name, ctype      string
			dflt             sql.NullString
		)
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return false, err
		}
		if name == col {
			return true, nil
		}
	}
	return false, rows.Err()
}

// Save: see Store.Save.
func (s *SQLite) Save(ctx context.Context, f *finding.Finding) (SaveResult, error) {
	if err := prepare(f, s.now()); err != nil {
		return SaveResult{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	res := SaveResult{ID: f.ID}

	var primaryID string
	err := s.db.QueryRowContext(ctx,
		`SELECT id FROM findings WHERE program=? AND dedup_key=? AND status!=? ORDER BY created_at LIMIT 1`,
		f.Program, f.DedupKey, string(finding.StatusDuplicate),
	).Scan(&primaryID)
	switch {
	case err == sql.ErrNoRows:
		// no primary => f becomes the primary
	case err != nil:
		return SaveResult{}, fmt.Errorf("store: check dedup: %w", err)
	default:
		if primaryID != f.ID {
			f.Status = finding.StatusDuplicate
			f.DuplicateOf = primaryID
			res.Deduplicated = true
			res.PrimaryID = primaryID
		}
	}

	doc, err := json.Marshal(f)
	if err != nil {
		return SaveResult{}, fmt.Errorf("store: marshal finding: %w", err)
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO findings (id,program,run_id,dedup_key,type,target,severity,status,duplicate_of,created_at,doc)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET
		   program=excluded.program, run_id=excluded.run_id, dedup_key=excluded.dedup_key,
		   type=excluded.type, target=excluded.target, severity=excluded.severity,
		   status=excluded.status, duplicate_of=excluded.duplicate_of,
		   created_at=excluded.created_at, doc=excluded.doc`,
		f.ID, f.Program, f.RunID, f.DedupKey, f.Type, f.Target,
		string(f.Severity), string(f.Status), f.DuplicateOf,
		f.CreatedAt.Time.UTC().Format(time.RFC3339), string(doc),
	)
	if err != nil {
		return SaveResult{}, fmt.Errorf("store: save finding: %w", err)
	}
	return res, nil
}

// Get: see Store.Get.
func (s *SQLite) Get(ctx context.Context, id string) (*finding.Finding, error) {
	var doc string
	err := s.db.QueryRowContext(ctx, `SELECT doc FROM findings WHERE id=?`, id).Scan(&doc)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: get finding: %w", err)
	}
	return decodeDoc(doc)
}

// List: see Store.List.
func (s *SQLite) List(ctx context.Context, q Query) ([]*finding.Finding, error) {
	var where []string
	var args []any

	if q.Program != "" {
		where = append(where, "program=?")
		args = append(args, q.Program)
	}
	if q.RunID != "" {
		where = append(where, "run_id=?")
		args = append(args, q.RunID)
	}
	if !q.IncludeDuplicates && !containsStatus(q.Statuses, finding.StatusDuplicate) {
		where = append(where, "status!=?")
		args = append(args, string(finding.StatusDuplicate))
	}
	if len(q.Statuses) > 0 {
		where = append(where, "status IN ("+placeholders(len(q.Statuses))+")")
		for _, st := range q.Statuses {
			args = append(args, string(st))
		}
	}
	if len(q.Severities) > 0 {
		where = append(where, "severity IN ("+placeholders(len(q.Severities))+")")
		for _, sv := range q.Severities {
			args = append(args, string(sv))
		}
	}
	if len(q.Types) > 0 {
		where = append(where, "type IN ("+placeholders(len(q.Types))+")")
		for _, ty := range q.Types {
			args = append(args, ty)
		}
	}

	query := `SELECT doc FROM findings`
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += ` ORDER BY CASE severity
		WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3
		WHEN 'low' THEN 2 WHEN 'info' THEN 1 ELSE 0 END DESC,
		created_at DESC`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query findings: %w", err)
	}
	defer rows.Close()

	var out []*finding.Finding
	for rows.Next() {
		var doc string
		if err := rows.Scan(&doc); err != nil {
			return nil, err
		}
		f, err := decodeDoc(doc)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// Programs: see Store.Programs.
func (s *SQLite) Programs(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT program FROM findings ORDER BY program`)
	if err != nil {
		return nil, fmt.Errorf("store: list programs: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// SetStatus: see Store.SetStatus.
func (s *SQLite) SetStatus(ctx context.Context, id string, status finding.Status, verifiedBy string) error {
	if !status.Valid() {
		return fmt.Errorf("store: invalid status: %q", status)
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if status == finding.StatusDuplicate && strings.TrimSpace(f.DuplicateOf) == "" {
		return fmt.Errorf("store: status duplicate is only set by the dedup path (duplicate_of is empty)")
	}
	f.Status = status
	if verifiedBy != "" {
		f.VerifiedBy = verifiedBy
	}
	now := finding.NewTime(s.now())
	f.UpdatedAt = &now

	doc, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("store: marshal finding: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `UPDATE findings SET status=?, doc=? WHERE id=?`,
		string(status), string(doc), id)
	if err != nil {
		return fmt.Errorf("store: update status: %w", err)
	}
	return nil
}

// UpdateContent: see Store.UpdateContent. It only updates the narrative fields
// in the JSON doc; the indexed columns (status/severity/dedup) do not change.
func (s *SQLite) UpdateContent(ctx context.Context, id, description, impact string, reproduction []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	f.Description = description
	f.Impact = impact
	f.Reproduction = reproduction
	now := finding.NewTime(s.now())
	f.UpdatedAt = &now

	doc, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("store: marshal finding: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE findings SET doc=? WHERE id=?`, string(doc), id); err != nil {
		return fmt.Errorf("store: update content: %w", err)
	}
	return nil
}

// SaveProgram: see Store.SaveProgram.
func (s *SQLite) SaveProgram(ctx context.Context, p Program) error {
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("store: program name is required")
	}
	in, _ := json.Marshal(p.InScope)
	out, _ := json.Marshal(p.OutScope)
	preset, _ := json.Marshal(p.Preset)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO programs (name,in_scope,out_scope,preset,updated_at) VALUES (?,?,?,?,?)
		 ON CONFLICT(name) DO UPDATE SET in_scope=excluded.in_scope, out_scope=excluded.out_scope, preset=excluded.preset, updated_at=excluded.updated_at`,
		p.Name, string(in), string(out), string(preset), s.now().UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("store: save program: %w", err)
	}
	return nil
}

// GetProgram: see Store.GetProgram.
func (s *SQLite) GetProgram(ctx context.Context, name string) (*Program, error) {
	var in, out, preset, upd string
	err := s.db.QueryRowContext(ctx, `SELECT in_scope,out_scope,preset,updated_at FROM programs WHERE name=?`, name).Scan(&in, &out, &preset, &upd)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: get program: %w", err)
	}
	return decodeProgram(name, in, out, preset, upd), nil
}

// ListPrograms: see Store.ListPrograms.
func (s *SQLite) ListPrograms(ctx context.Context) ([]*Program, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name,in_scope,out_scope,preset,updated_at FROM programs ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("store: list programs: %w", err)
	}
	defer rows.Close()
	var out []*Program
	for rows.Next() {
		var name, in, outs, preset, upd string
		if err := rows.Scan(&name, &in, &outs, &preset, &upd); err != nil {
			return nil, err
		}
		out = append(out, decodeProgram(name, in, outs, preset, upd))
	}
	return out, rows.Err()
}

// DeleteProgram: see Store.DeleteProgram. Only the program definition row is
// deleted; the findings and audit tables are not touched.
func (s *SQLite) DeleteProgram(ctx context.Context, name string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM programs WHERE name=?`, name)
	if err != nil {
		return fmt.Errorf("store: delete program: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteFindingsByProgram: see Store.DeleteFindingsByProgram. Dedup is enforced
// directly from the findings rows (there is no separate bookkeeping table), so
// deleting the rows resets the dedup state automatically. The lock is held so
// it does not race with Save's dedup decision. The program definition and the
// audit are not touched.
func (s *SQLite) DeleteFindingsByProgram(ctx context.Context, program string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.ExecContext(ctx, `DELETE FROM findings WHERE program=?`, program)
	if err != nil {
		return 0, fmt.Errorf("store: delete program findings: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func decodeProgram(name, in, out, preset, upd string) *Program {
	p := &Program{Name: name}
	_ = json.Unmarshal([]byte(in), &p.InScope)
	_ = json.Unmarshal([]byte(out), &p.OutScope)
	if preset != "" {
		_ = json.Unmarshal([]byte(preset), &p.Preset)
	}
	p.UpdatedAt, _ = time.Parse(time.RFC3339, upd)
	return p
}

// ---- UserStore (RBAC) ----

// CreateUser: see UserStore.CreateUser.
func (s *SQLite) CreateUser(ctx context.Context, u User) error {
	if strings.TrimSpace(u.Username) == "" {
		return fmt.Errorf("store: username is required")
	}
	if u.Created.IsZero() {
		u.Created = s.now().UTC()
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO users (username, role, pass_hash, created_at) VALUES (?,?,?,?)`,
		u.Username, u.Role, u.PassHash, u.Created.UTC().Format(time.RFC3339))
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return ErrUserExists
		}
		return fmt.Errorf("store: create user: %w", err)
	}
	return nil
}

// GetUser: see UserStore.GetUser.
func (s *SQLite) GetUser(ctx context.Context, username string) (*User, error) {
	var role, hash, created string
	err := s.db.QueryRowContext(ctx, `SELECT role, pass_hash, created_at FROM users WHERE username=?`, username).Scan(&role, &hash, &created)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: get user: %w", err)
	}
	t, _ := time.Parse(time.RFC3339, created)
	return &User{Username: username, Role: role, PassHash: hash, Created: t}, nil
}

// ListUsers: see UserStore.ListUsers.
func (s *SQLite) ListUsers(ctx context.Context) ([]*User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT username, role, pass_hash, created_at FROM users ORDER BY username`)
	if err != nil {
		return nil, fmt.Errorf("store: list users: %w", err)
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		var name, role, hash, created string
		if err := rows.Scan(&name, &role, &hash, &created); err != nil {
			return nil, err
		}
		t, _ := time.Parse(time.RFC3339, created)
		out = append(out, &User{Username: name, Role: role, PassHash: hash, Created: t})
	}
	return out, rows.Err()
}

// DeleteUser: see UserStore.DeleteUser.
func (s *SQLite) DeleteUser(ctx context.Context, username string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE username=?`, username)
	if err != nil {
		return fmt.Errorf("store: delete user: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetPassword: see UserStore.SetPassword.
func (s *SQLite) SetPassword(ctx context.Context, username, passHash string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET pass_hash=? WHERE username=?`, passHash, username)
	if err != nil {
		return fmt.Errorf("store: set password: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// CountUsers: see UserStore.CountUsers.
func (s *SQLite) CountUsers(ctx context.Context) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count users: %w", err)
	}
	return n, nil
}

// Close closes the database.
func (s *SQLite) Close() error { return s.db.Close() }

func decodeDoc(doc string) (*finding.Finding, error) {
	var f finding.Finding
	if err := json.Unmarshal([]byte(doc), &f); err != nil {
		return nil, fmt.Errorf("store: corrupt finding document: %w", err)
	}
	return &f, nil
}

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.Repeat("?,", n-1) + "?"
}
