package secret

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// SQLiteVault adalah Vault berbasis SQLite (terisolasi; default di file terpisah
// dari temuan). Hanya ciphertext yang disimpan — plaintext tak pernah menyentuh
// disk.
type SQLiteVault struct {
	db       *sql.DB
	kr       *Keyring
	now      func() time.Time
	onReveal func(scope, name string)
}

// SetRevealHook: lihat Vault.SetRevealHook.
func (v *SQLiteVault) SetRevealHook(fn func(scope, name string)) { v.onReveal = fn }

// OpenSQLiteVault membuka/membuat vault pada path.
func OpenSQLiteVault(path string, kr *Keyring) (*SQLiteVault, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("secret: buka vault: %w", err)
	}
	db.SetMaxOpenConns(1)
	v := &SQLiteVault{db: db, kr: kr, now: time.Now}
	if err := v.init(); err != nil {
		db.Close()
		return nil, err
	}
	return v, nil
}

func (v *SQLiteVault) init() error {
	stmts := []string{
		`PRAGMA journal_mode=WAL;`,
		`PRAGMA busy_timeout=5000;`,
		`CREATE TABLE IF NOT EXISTS secrets (
			scope      TEXT NOT NULL,
			name       TEXT NOT NULL,
			token      TEXT NOT NULL,
			key_id     TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			PRIMARY KEY(scope, name)
		);`,
	}
	for _, q := range stmts {
		if _, err := v.db.Exec(q); err != nil {
			return fmt.Errorf("secret: init vault: %w", err)
		}
	}
	return nil
}

func (v *SQLiteVault) Put(ctx context.Context, scope, name string, value []byte) error {
	if name = strings.TrimSpace(name); name == "" {
		return fmt.Errorf("secret: nama wajib")
	}
	token, err := v.kr.Encrypt(value)
	if err != nil {
		return err
	}
	now := v.now().UTC().Format(time.RFC3339)
	_, err = v.db.ExecContext(ctx,
		`INSERT INTO secrets (scope,name,token,key_id,created_at,updated_at)
		 VALUES (?,?,?,?,?,?)
		 ON CONFLICT(scope,name) DO UPDATE SET
		   token=excluded.token, key_id=excluded.key_id, updated_at=excluded.updated_at`,
		normScope(scope), name, token, v.kr.ActiveID(), now, now)
	if err != nil {
		return fmt.Errorf("secret: simpan: %w", err)
	}
	return nil
}

func (v *SQLiteVault) Reveal(ctx context.Context, scope, name string) ([]byte, error) {
	var token string
	err := v.db.QueryRowContext(ctx, `SELECT token FROM secrets WHERE scope=? AND name=?`,
		normScope(scope), name).Scan(&token)
	if err == sql.ErrNoRows {
		return nil, ErrSecretNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("secret: ambil: %w", err)
	}
	pt, derr := v.kr.Decrypt(token)
	if derr == nil && v.onReveal != nil {
		v.onReveal(normScope(scope), name)
	}
	return pt, derr
}

func (v *SQLiteVault) List(ctx context.Context, scope string) ([]Meta, error) {
	rows, err := v.db.QueryContext(ctx,
		`SELECT name,key_id,created_at,updated_at FROM secrets WHERE scope=? ORDER BY name`,
		normScope(scope))
	if err != nil {
		return nil, fmt.Errorf("secret: daftar: %w", err)
	}
	defer rows.Close()
	var out []Meta
	for rows.Next() {
		var name, keyID, c, u string
		if err := rows.Scan(&name, &keyID, &c, &u); err != nil {
			return nil, err
		}
		ct, _ := time.Parse(time.RFC3339, c)
		ut, _ := time.Parse(time.RFC3339, u)
		out = append(out, Meta{Scope: normScope(scope), Name: name, KeyID: keyID, CreatedAt: ct, UpdatedAt: ut})
	}
	return out, rows.Err()
}

func (v *SQLiteVault) Delete(ctx context.Context, scope, name string) error {
	res, err := v.db.ExecContext(ctx, `DELETE FROM secrets WHERE scope=? AND name=?`, normScope(scope), name)
	if err != nil {
		return fmt.Errorf("secret: hapus: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrSecretNotFound
	}
	return nil
}

func (v *SQLiteVault) Rotate(ctx context.Context) (int, error) {
	rows, err := v.db.QueryContext(ctx, `SELECT scope,name,token FROM secrets`)
	if err != nil {
		return 0, fmt.Errorf("secret: rotate query: %w", err)
	}
	type item struct{ scope, name, token string }
	var items []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.scope, &it.name, &it.token); err != nil {
			rows.Close()
			return 0, err
		}
		items = append(items, it)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	n := 0
	now := v.now().UTC().Format(time.RFC3339)
	for _, it := range items {
		pt, err := v.kr.Decrypt(it.token)
		if err != nil {
			return n, err
		}
		token, err := v.kr.Encrypt(pt)
		if err != nil {
			return n, err
		}
		if _, err := v.db.ExecContext(ctx,
			`UPDATE secrets SET token=?, key_id=?, updated_at=? WHERE scope=? AND name=?`,
			token, v.kr.ActiveID(), now, it.scope, it.name); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func (v *SQLiteVault) Close() error { return v.db.Close() }
