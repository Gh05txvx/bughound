package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// AIAnalysis is the result of the AI what-if analysis for one finding, CACHED so
// the Claude API is not called (and loaded) every time the finding is opened.
// Payload = the JSON of the part the LLM reasons out (why/decision/hypotheses).
// The deterministic part (target, seed hints, safety) is rebuilt at render time
// and does not need caching.
//
// SourceHash binds the cache to the finding content + model: when the finding
// content changes or the model is switched, the hash differs → the stale cache
// is dropped and regenerated. The secret (the Claude API key) is NOT here; it
// lives in the encrypted vault (the secret isolation principle).
type AIAnalysis struct {
	FindingID  string
	Program    string
	Model      string
	SourceHash string
	Payload    string // JSON of the LLM's reasoning result
	CreatedAt  time.Time
}

// AIStore holds the AI analysis cache + non-secret app settings (e.g. the chosen
// Claude model). *SQLite and *Mem implement it; the web layer reaches it through
// a type assertion (graceful degradation when the store does not support it),
// like CatalogStore/UserStore.
type AIStore interface {
	// GetAIAnalysis gets the cached analysis of a finding; ErrNotFound when there is none.
	GetAIAnalysis(ctx context.Context, findingID string) (*AIAnalysis, error)
	// PutAIAnalysis saves/overwrites the cached analysis of a finding.
	PutAIAnalysis(ctx context.Context, a AIAnalysis) error
	// DeleteAIAnalysisByProgram deletes every cached analysis of a program (called
	// when the program's findings are cleared, so no cache is left orphaned).
	DeleteAIAnalysisByProgram(ctx context.Context, program string) (int, error)
	// GetSetting gets an app setting (non-secret); "" when there is none.
	GetSetting(ctx context.Context, key string) (string, error)
	// PutSetting saves an app setting (non-secret).
	PutSetting(ctx context.Context, key, value string) error
}

// ---- SQLite ----

func (s *SQLite) GetAIAnalysis(ctx context.Context, findingID string) (*AIAnalysis, error) {
	var a AIAnalysis
	var created string
	err := s.db.QueryRowContext(ctx,
		`SELECT finding_id, program, model, source_hash, payload, created_at FROM ai_analysis WHERE finding_id=?`,
		findingID).Scan(&a.FindingID, &a.Program, &a.Model, &a.SourceHash, &a.Payload, &created)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: get AI analysis: %w", err)
	}
	a.CreatedAt, _ = time.Parse(time.RFC3339, created)
	return &a, nil
}

func (s *SQLite) PutAIAnalysis(ctx context.Context, a AIAnalysis) error {
	now := a.CreatedAt
	if now.IsZero() {
		now = s.now()
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO ai_analysis (finding_id, program, model, source_hash, payload, created_at)
		 VALUES (?,?,?,?,?,?)
		 ON CONFLICT(finding_id) DO UPDATE SET
		   program=excluded.program, model=excluded.model, source_hash=excluded.source_hash,
		   payload=excluded.payload, created_at=excluded.created_at`,
		a.FindingID, a.Program, a.Model, a.SourceHash, a.Payload, now.UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("store: save AI analysis: %w", err)
	}
	return nil
}

func (s *SQLite) DeleteAIAnalysisByProgram(ctx context.Context, program string) (int, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM ai_analysis WHERE program=?`, program)
	if err != nil {
		return 0, fmt.Errorf("store: delete AI analysis: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (s *SQLite) GetSetting(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT v FROM app_settings WHERE k=?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("store: get setting: %w", err)
	}
	return v, nil
}

func (s *SQLite) PutSetting(ctx context.Context, key, value string) error {
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO app_settings (k,v) VALUES (?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`,
		key, value); err != nil {
		return fmt.Errorf("store: save setting: %w", err)
	}
	return nil
}

// ---- Mem ----

func (m *Mem) GetAIAnalysis(ctx context.Context, findingID string) (*AIAnalysis, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	a, ok := m.aiAnalyses[findingID]
	if !ok {
		return nil, ErrNotFound
	}
	cp := a
	return &cp, nil
}

func (m *Mem) PutAIAnalysis(ctx context.Context, a AIAnalysis) error {
	if a.CreatedAt.IsZero() {
		a.CreatedAt = m.now().UTC()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.aiAnalyses == nil {
		m.aiAnalyses = map[string]AIAnalysis{}
	}
	m.aiAnalyses[a.FindingID] = a
	return nil
}

func (m *Mem) DeleteAIAnalysisByProgram(ctx context.Context, program string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for id, a := range m.aiAnalyses {
		if a.Program == program {
			delete(m.aiAnalyses, id)
			n++
		}
	}
	return n, nil
}

func (m *Mem) GetSetting(ctx context.Context, key string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.settings[key], nil
}

func (m *Mem) PutSetting(ctx context.Context, key, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.settings == nil {
		m.settings = map[string]string{}
	}
	m.settings[key] = value
	return nil
}
