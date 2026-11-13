package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// AIAnalysis adalah hasil analisis what-if AI untuk satu temuan, DI-CACHE agar
// tak memanggil (dan membebani) Claude API tiap kali temuan dibuka. Payload = JSON
// bagian yang ditalar LLM (why/decision/hypotheses). Bagian deterministik (target,
// seed hint, safety) dibangun ulang saat render — tak perlu di-cache.
//
// SourceHash mengikat cache ke konten temuan + model: bila konten temuan berubah
// atau model diganti, hash beda → cache basi dibuang & regenerasi. Rahasia (API
// key Claude) TIDAK di sini — itu di vault terenkripsi (prinsip secret-isolasi).
type AIAnalysis struct {
	FindingID  string
	Program    string
	Model      string
	SourceHash string
	Payload    string // JSON hasil penalaran LLM
	CreatedAt  time.Time
}

// AIStore menyimpan cache analisis AI + setelan aplikasi non-rahasia (mis. model
// Claude terpilih). Diimplementasikan oleh *SQLite dan *Mem; web mengaksesnya
// lewat type assertion (degradasi mulus bila store tak mendukung), sama seperti
// CatalogStore/UserStore.
type AIStore interface {
	// GetAIAnalysis mengambil cache analisis sebuah temuan; ErrNotFound bila tak ada.
	GetAIAnalysis(ctx context.Context, findingID string) (*AIAnalysis, error)
	// PutAIAnalysis menyimpan/menimpa cache analisis sebuah temuan.
	PutAIAnalysis(ctx context.Context, a AIAnalysis) error
	// DeleteAIAnalysisByProgram menghapus semua cache analisis milik sebuah program
	// (dipanggil saat temuan program dibersihkan agar tak ada cache yatim).
	DeleteAIAnalysisByProgram(ctx context.Context, program string) (int, error)
	// GetSetting mengambil setelan aplikasi (non-rahasia); "" bila tak ada.
	GetSetting(ctx context.Context, key string) (string, error)
	// PutSetting menyimpan setelan aplikasi (non-rahasia).
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
		return nil, fmt.Errorf("store: ambil analisis AI: %w", err)
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
		return fmt.Errorf("store: simpan analisis AI: %w", err)
	}
	return nil
}

func (s *SQLite) DeleteAIAnalysisByProgram(ctx context.Context, program string) (int, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM ai_analysis WHERE program=?`, program)
	if err != nil {
		return 0, fmt.Errorf("store: hapus analisis AI: %w", err)
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
		return "", fmt.Errorf("store: ambil setelan: %w", err)
	}
	return v, nil
}

func (s *SQLite) PutSetting(ctx context.Context, key, value string) error {
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO app_settings (k,v) VALUES (?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`,
		key, value); err != nil {
		return fmt.Errorf("store: simpan setelan: %w", err)
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
