package audit

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// SQLiteLog adalah Log berbasis SQLite (persisten, append-only secara kontrak:
// tak ada metode hapus/ubah). Integritas dijaga rantai HMAC + Verify.
type SQLiteLog struct {
	db       *sql.DB
	key      []byte
	now      func() time.Time
	mu       sync.Mutex // atomisitas seq + prev_hash
	anchorer Anchorer   // opsional: attestation eksternal (BH-F06)
}

// Option mengonfigurasi SQLiteLog saat dibuka.
type Option func(*SQLiteLog)

// WithAnchorer memasang attestation eksternal: head rantai di-anchor tiap
// Append, dan Verify memeriksa store konsisten dengan anchor (deteksi
// trunkasi/rollback/penghapusan total store — BH-F06).
func WithAnchorer(a Anchorer) Option {
	return func(l *SQLiteLog) { l.anchorer = a }
}

// OpenSQLiteLog membuka/membuat log pada path dengan kunci HMAC key.
func OpenSQLiteLog(path string, key []byte, opts ...Option) (*SQLiteLog, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("audit: buka log: %w", err)
	}
	db.SetMaxOpenConns(1)
	l := &SQLiteLog{db: db, key: key, now: time.Now}
	for _, o := range opts {
		o(l)
	}
	if err := l.init(); err != nil {
		db.Close()
		return nil, err
	}
	return l, nil
}

func (l *SQLiteLog) init() error {
	stmts := []string{
		`PRAGMA journal_mode=WAL;`,
		`PRAGMA busy_timeout=5000;`,
		`CREATE TABLE IF NOT EXISTS audit_log (
			seq       INTEGER PRIMARY KEY,
			time      TEXT NOT NULL,
			kind      TEXT NOT NULL,
			program   TEXT,
			run_id    TEXT,
			target    TEXT,
			allowed   INTEGER,
			reason    TEXT,
			layer     TEXT,
			message   TEXT,
			prev_hash TEXT,
			hash      TEXT NOT NULL
		);`,
	}
	for _, q := range stmts {
		if _, err := l.db.Exec(q); err != nil {
			return fmt.Errorf("audit: init: %w", err)
		}
	}
	return nil
}

func (l *SQLiteLog) Append(ctx context.Context, e Event) (Event, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	var lastSeq int64
	var lastHash string
	err := l.db.QueryRowContext(ctx, `SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(&lastSeq, &lastHash)
	if err != nil && err != sql.ErrNoRows {
		return Event{}, fmt.Errorf("audit: baca entri terakhir: %w", err)
	}

	if e.Time.IsZero() {
		e.Time = l.now().UTC()
	}
	e.Seq = lastSeq + 1
	e.PrevHash = lastHash
	e.Hash = mac(l.key, lastHash, e)

	_, err = l.db.ExecContext(ctx,
		`INSERT INTO audit_log (seq,time,kind,program,run_id,target,allowed,reason,layer,message,prev_hash,hash)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		e.Seq, e.Time.UTC().Format(time.RFC3339Nano), e.Kind, e.Program, e.RunID, e.Target,
		boolToInt(e.Allowed), e.Reason, e.Layer, e.Message, e.PrevHash, e.Hash)
	if err != nil {
		return Event{}, fmt.Errorf("audit: simpan: %w", err)
	}
	// Attestation eksternal (best-effort): entri sudah tersimpan; kegagalan
	// anchor tak membatalkan entri (rantai HMAC di store tetap utuh).
	if l.anchorer != nil {
		_ = l.anchorer.WriteAnchor(Anchor{Seq: e.Seq, Hash: e.Hash, At: e.Time})
	}
	return e, nil
}

func (l *SQLiteLog) List(ctx context.Context, f Filter) ([]Event, error) {
	var where []string
	var args []any
	if f.Program != "" {
		where = append(where, "program=?")
		args = append(args, f.Program)
	}
	if f.RunID != "" {
		where = append(where, "run_id=?")
		args = append(args, f.RunID)
	}
	if f.Kind != "" {
		where = append(where, "kind=?")
		args = append(args, f.Kind)
	}
	q := `SELECT seq,time,kind,program,run_id,target,allowed,reason,layer,message,prev_hash,hash FROM audit_log`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY seq DESC" // terbaru dulu
	if f.Limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", f.Limit)
	}
	rows, err := l.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("audit: query: %w", err)
	}
	defer rows.Close()
	return scanEvents(rows)
}

func (l *SQLiteLog) Verify(ctx context.Context) (Result, error) {
	rows, err := l.db.QueryContext(ctx,
		`SELECT seq,time,kind,program,run_id,target,allowed,reason,layer,message,prev_hash,hash FROM audit_log ORDER BY seq ASC`)
	if err != nil {
		return Result{}, fmt.Errorf("audit: verify query: %w", err)
	}
	defer rows.Close()
	events, err := scanEvents(rows)
	if err != nil {
		return Result{}, err
	}
	res := verifyChain(l.key, events)
	if !res.OK {
		return res, nil
	}
	// Cross-check attestation eksternal: tangkap trunkasi/rollback/penghapusan
	// total store yang tak terlihat oleh rantai internal (BH-F06).
	if l.anchorer != nil {
		anchors, aerr := l.anchorer.Anchors()
		if aerr != nil {
			return Result{}, fmt.Errorf("audit: baca anchor: %w", aerr)
		}
		if ares := verifyAnchors(l.key, events, anchors); !ares.OK {
			return ares, nil
		}
		res.Anchors = int64(len(anchors))
	}
	return res, nil
}

func (l *SQLiteLog) Close() error { return l.db.Close() }

func scanEvents(rows *sql.Rows) ([]Event, error) {
	var out []Event
	for rows.Next() {
		var e Event
		var tstr string
		var allowed int
		if err := rows.Scan(&e.Seq, &tstr, &e.Kind, &e.Program, &e.RunID, &e.Target,
			&allowed, &e.Reason, &e.Layer, &e.Message, &e.PrevHash, &e.Hash); err != nil {
			return nil, err
		}
		e.Time, _ = time.Parse(time.RFC3339Nano, tstr)
		e.Allowed = allowed != 0
		out = append(out, e)
	}
	return out, rows.Err()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
