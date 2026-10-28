// Package store menyimpan temuan dalam Skema Temuan Seragam (BH-SPEC-FINDING),
// terstruktur per-program dan per-run, dan menyediakan query untuk triase serta
// report. Dedup ditegakkan berdasarkan (program, dedup_key): temuan pertama
// untuk sebuah dedup_key menjadi utama, kemunculan berikutnya ditandai duplikat
// dengan duplicate_of menunjuk ke yang utama.
package store

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"bughound/internal/finding"
)

// Store adalah kontrak penyimpanan temuan. Implementasi (in-memory, SQLite)
// harus menegakkan dedup yang sama.
type Store interface {
	// Save menyimpan satu temuan. Bila ID/dedup_key/created_at kosong, diisi
	// otomatis. Mengembalikan apakah temuan dikenali sebagai duplikat.
	Save(ctx context.Context, f *finding.Finding) (SaveResult, error)
	// Get mengambil satu temuan berdasarkan id.
	Get(ctx context.Context, id string) (*finding.Finding, error)
	// List mengembalikan temuan yang cocok Query, diurut severity terberat dulu.
	List(ctx context.Context, q Query) ([]*finding.Finding, error)
	// Programs mengembalikan nama program berbeda yang punya temuan tersimpan.
	Programs(ctx context.Context) ([]string, error)
	// SaveProgram menyimpan/memperbarui definisi scope sebuah program (persisten).
	SaveProgram(ctx context.Context, p Program) error
	// GetProgram mengambil definisi program; ErrNotFound bila tak ada.
	GetProgram(ctx context.Context, name string) (*Program, error)
	// ListPrograms mengembalikan semua program tersimpan, terurut nama.
	ListPrograms(ctx context.Context) ([]*Program, error)
	// SetStatus mengubah status triase sebuah temuan.
	SetStatus(ctx context.Context, id string, status finding.Status, verifiedBy string) error
	// Close melepaskan sumber daya (no-op untuk in-memory).
	Close() error
}

// SaveResult melaporkan hasil penyimpanan satu temuan.
type SaveResult struct {
	ID           string
	Deduplicated bool
	PrimaryID    string // id temuan utama bila Deduplicated
}

// Query memfilter daftar temuan. Secara default duplikat disembunyikan kecuali
// diminta eksplisit (IncludeDuplicates atau Statuses memuat "duplicate").
type Query struct {
	Program           string
	RunID             string
	Statuses          []finding.Status
	Severities        []finding.Severity
	Types             []string
	IncludeDuplicates bool
}

// ErrNotFound dikembalikan Get/SetStatus bila id tak ada.
var ErrNotFound = errors.New("store: temuan tidak ditemukan")

// ErrUserExists dikembalikan CreateUser bila username sudah dipakai.
var ErrUserExists = errors.New("store: username sudah ada")

// Program menyimpan definisi scope sebuah program bounty (persisten).
type Program struct {
	Name      string
	InScope   []string
	OutScope  []string
	UpdatedAt time.Time
}

// User adalah akun RBAC (lihat internal/auth untuk peran & hashing). PassHash
// berisi hash PBKDF2 ber-salt; kata sandi mentah TIDAK pernah disimpan.
type User struct {
	Username string
	Role     string // "admin" | "operator" | "viewer" (auth.Role)
	PassHash string
	Created  time.Time
}

// UserStore mengelola akun RBAC. Mem dan SQLite keduanya mengimplementasikannya,
// jadi objek store tunggal menyediakan temuan sekaligus pengguna.
type UserStore interface {
	// CreateUser menyimpan user baru; ErrUserExists bila username sudah ada.
	CreateUser(ctx context.Context, u User) error
	// GetUser mengambil user; ErrNotFound bila tak ada.
	GetUser(ctx context.Context, username string) (*User, error)
	// ListUsers mengembalikan semua user, terurut username.
	ListUsers(ctx context.Context) ([]*User, error)
	// DeleteUser menghapus user; ErrNotFound bila tak ada.
	DeleteUser(ctx context.Context, username string) error
	// SetPassword memperbarui hash kata sandi user; ErrNotFound bila tak ada.
	SetPassword(ctx context.Context, username, passHash string) error
	// CountUsers mengembalikan jumlah user (untuk bootstrap admin awal).
	CountUsers(ctx context.Context) (int, error)
}

// prepare mengisi field turunan (id, schema_version, dedup_key, created_at)
// yang masih kosong lalu memvalidasi temuan.
func prepare(f *finding.Finding, now time.Time) error {
	if strings.TrimSpace(f.ID) == "" {
		id, err := newID()
		if err != nil {
			return err
		}
		f.ID = id
	}
	return f.Finalize(now)
}

// newID menghasilkan UUIDv4 tanpa dependency eksternal.
func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("store: gagal membuat id: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // versi 4
	b[8] = (b[8] & 0x3f) | 0x80 // varian RFC 4122
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// clone membuat salinan dalam agar store tidak berbagi state dengan pemanggil.
func clone(f *finding.Finding) *finding.Finding {
	b, _ := json.Marshal(f)
	var c finding.Finding
	_ = json.Unmarshal(b, &c)
	return &c
}

// severityRank: makin besar makin berat, untuk pengurutan prioritas.
func severityRank(s finding.Severity) int {
	switch s {
	case finding.SeverityCritical:
		return 5
	case finding.SeverityHigh:
		return 4
	case finding.SeverityMedium:
		return 3
	case finding.SeverityLow:
		return 2
	case finding.SeverityInfo:
		return 1
	}
	return 0
}

func containsStatus(ss []finding.Status, s finding.Status) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func containsSeverity(ss []finding.Severity, s finding.Severity) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func containsString(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
