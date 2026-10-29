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

	_ "modernc.org/sqlite" // driver "sqlite" (pure-Go, tanpa cgo => tetap binary tunggal)
)

// SQLite adalah Store berbasis SQLite. Temuan disimpan utuh sebagai dokumen JSON
// (skema berversi di JSON), dengan kolom terindeks untuk query triase. Dedup
// ditegakkan sama seperti Mem: per (program, dedup_key).
type SQLite struct {
	db  *sql.DB
	now func() time.Time
	mu  sync.Mutex // menjaga atomisitas keputusan dedup (cek + tulis)
}

// OpenSQLite membuka/membuat database pada path (atau ":memory:").
func OpenSQLite(path string) (*SQLite, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("store: buka sqlite: %w", err)
	}
	db.SetMaxOpenConns(1) // hindari "database is locked"
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
			updated_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS users (
			username   TEXT PRIMARY KEY,
			role       TEXT NOT NULL,
			pass_hash  TEXT NOT NULL,
			created_at TEXT NOT NULL
		);`,
		// Bank Payload (BH-SPEC-PAYLOAD): katalog metadata di atas template native.
		// Entri utuh disimpan sebagai doc JSON; kolom terindeks untuk filter UI.
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
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("store: init skema: %w", err)
		}
	}
	return nil
}

// Save: lihat Store.Save.
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
		// tak ada primary => f menjadi primary
	case err != nil:
		return SaveResult{}, fmt.Errorf("store: cek dedup: %w", err)
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
		return SaveResult{}, fmt.Errorf("store: marshal temuan: %w", err)
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
		return SaveResult{}, fmt.Errorf("store: simpan temuan: %w", err)
	}
	return res, nil
}

// Get: lihat Store.Get.
func (s *SQLite) Get(ctx context.Context, id string) (*finding.Finding, error) {
	var doc string
	err := s.db.QueryRowContext(ctx, `SELECT doc FROM findings WHERE id=?`, id).Scan(&doc)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: ambil temuan: %w", err)
	}
	return decodeDoc(doc)
}

// List: lihat Store.List.
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
		return nil, fmt.Errorf("store: query temuan: %w", err)
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

// Programs: lihat Store.Programs.
func (s *SQLite) Programs(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT program FROM findings ORDER BY program`)
	if err != nil {
		return nil, fmt.Errorf("store: daftar program: %w", err)
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

// SetStatus: lihat Store.SetStatus.
func (s *SQLite) SetStatus(ctx context.Context, id string, status finding.Status, verifiedBy string) error {
	if !status.Valid() {
		return fmt.Errorf("store: status tidak sah: %q", status)
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if status == finding.StatusDuplicate && strings.TrimSpace(f.DuplicateOf) == "" {
		return fmt.Errorf("store: status duplicate hanya lewat jalur dedup (duplicate_of kosong)")
	}
	f.Status = status
	if verifiedBy != "" {
		f.VerifiedBy = verifiedBy
	}
	now := finding.NewTime(s.now())
	f.UpdatedAt = &now

	doc, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("store: marshal temuan: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `UPDATE findings SET status=?, doc=? WHERE id=?`,
		string(status), string(doc), id)
	if err != nil {
		return fmt.Errorf("store: update status: %w", err)
	}
	return nil
}

// SaveProgram: lihat Store.SaveProgram.
func (s *SQLite) SaveProgram(ctx context.Context, p Program) error {
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("store: nama program wajib")
	}
	in, _ := json.Marshal(p.InScope)
	out, _ := json.Marshal(p.OutScope)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO programs (name,in_scope,out_scope,updated_at) VALUES (?,?,?,?)
		 ON CONFLICT(name) DO UPDATE SET in_scope=excluded.in_scope, out_scope=excluded.out_scope, updated_at=excluded.updated_at`,
		p.Name, string(in), string(out), s.now().UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("store: simpan program: %w", err)
	}
	return nil
}

// GetProgram: lihat Store.GetProgram.
func (s *SQLite) GetProgram(ctx context.Context, name string) (*Program, error) {
	var in, out, upd string
	err := s.db.QueryRowContext(ctx, `SELECT in_scope,out_scope,updated_at FROM programs WHERE name=?`, name).Scan(&in, &out, &upd)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: ambil program: %w", err)
	}
	return decodeProgram(name, in, out, upd), nil
}

// ListPrograms: lihat Store.ListPrograms.
func (s *SQLite) ListPrograms(ctx context.Context) ([]*Program, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name,in_scope,out_scope,updated_at FROM programs ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("store: daftar program: %w", err)
	}
	defer rows.Close()
	var out []*Program
	for rows.Next() {
		var name, in, outs, upd string
		if err := rows.Scan(&name, &in, &outs, &upd); err != nil {
			return nil, err
		}
		out = append(out, decodeProgram(name, in, outs, upd))
	}
	return out, rows.Err()
}

// DeleteProgram: lihat Store.DeleteProgram. Hanya baris definisi program yang
// dihapus; tabel findings & audit tidak disentuh.
func (s *SQLite) DeleteProgram(ctx context.Context, name string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM programs WHERE name=?`, name)
	if err != nil {
		return fmt.Errorf("store: hapus program: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func decodeProgram(name, in, out, upd string) *Program {
	p := &Program{Name: name}
	_ = json.Unmarshal([]byte(in), &p.InScope)
	_ = json.Unmarshal([]byte(out), &p.OutScope)
	p.UpdatedAt, _ = time.Parse(time.RFC3339, upd)
	return p
}

// ---- UserStore (RBAC) ----

// CreateUser: lihat UserStore.CreateUser.
func (s *SQLite) CreateUser(ctx context.Context, u User) error {
	if strings.TrimSpace(u.Username) == "" {
		return fmt.Errorf("store: username wajib")
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
		return fmt.Errorf("store: buat user: %w", err)
	}
	return nil
}

// GetUser: lihat UserStore.GetUser.
func (s *SQLite) GetUser(ctx context.Context, username string) (*User, error) {
	var role, hash, created string
	err := s.db.QueryRowContext(ctx, `SELECT role, pass_hash, created_at FROM users WHERE username=?`, username).Scan(&role, &hash, &created)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: ambil user: %w", err)
	}
	t, _ := time.Parse(time.RFC3339, created)
	return &User{Username: username, Role: role, PassHash: hash, Created: t}, nil
}

// ListUsers: lihat UserStore.ListUsers.
func (s *SQLite) ListUsers(ctx context.Context) ([]*User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT username, role, pass_hash, created_at FROM users ORDER BY username`)
	if err != nil {
		return nil, fmt.Errorf("store: daftar user: %w", err)
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

// DeleteUser: lihat UserStore.DeleteUser.
func (s *SQLite) DeleteUser(ctx context.Context, username string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE username=?`, username)
	if err != nil {
		return fmt.Errorf("store: hapus user: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetPassword: lihat UserStore.SetPassword.
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

// CountUsers: lihat UserStore.CountUsers.
func (s *SQLite) CountUsers(ctx context.Context) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: hitung user: %w", err)
	}
	return n, nil
}

// Close menutup database.
func (s *SQLite) Close() error { return s.db.Close() }

func decodeDoc(doc string) (*finding.Finding, error) {
	var f finding.Finding
	if err := json.Unmarshal([]byte(doc), &f); err != nil {
		return nil, fmt.Errorf("store: dokumen temuan rusak: %w", err)
	}
	return &f, nil
}

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.Repeat("?,", n-1) + "?"
}
