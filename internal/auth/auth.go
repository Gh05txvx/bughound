// Package auth menyediakan peran RBAC dan hashing kata sandi untuk bughound.
//
// Hashing memakai PBKDF2-HMAC-SHA256 dari pustaka standar (crypto/pbkdf2, tersedia
// sejak Go 1.24) sehingga TIDAK menambah dependensi pihak ketiga. Setiap hash
// memakai salt acak dan di-encode self-describing (algoritma + iterasi + salt),
// jadi parameter bisa dinaikkan tanpa memutus hash lama. Verifikasi memakai
// perbandingan waktu-tetap. Kata sandi mentah tak pernah disimpan atau dicatat.
package auth

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Role adalah peran RBAC. Hirarki hak: viewer < operator < admin.
//
//   - viewer   : hanya baca (dashboard, findings, report, audit).
//   - operator : viewer + menjalankan scan, triase, kelola program, capture.
//   - admin    : operator + kelola pengguna.
type Role string

const (
	RoleAdmin    Role = "admin"
	RoleOperator Role = "operator"
	RoleViewer   Role = "viewer"
)

// Roles mengembalikan daftar peran yang dikenal (untuk mengisi dropdown UI).
func Roles() []Role { return []Role{RoleAdmin, RoleOperator, RoleViewer} }

// Valid melaporkan apakah r adalah salah satu peran yang dikenal.
func (r Role) Valid() bool {
	switch r {
	case RoleAdmin, RoleOperator, RoleViewer:
		return true
	}
	return false
}

// CanRead: semua peran yang valid boleh membaca (viewer ke atas).
func CanRead(r Role) bool { return r.Valid() }

// CanWrite: operator & admin boleh mengubah state (scan, triase, program, secret).
func CanWrite(r Role) bool { return r == RoleOperator || r == RoleAdmin }

// CanAdmin: hanya admin (mengelola pengguna).
func CanAdmin(r Role) bool { return r == RoleAdmin }

// Parameter PBKDF2. Iterasi dipilih konservatif untuk login interaktif pada
// peladen kecil; tersimpan di hash sehingga bisa dinaikkan belakangan.
const (
	pbkdfIter   = 210_000
	pbkdfKeyLen = 32
	saltLen     = 16
	hashPrefix  = "pbkdf2_sha256"
)

// ErrEmptyPassword dikembalikan HashPassword bila kata sandi kosong.
var ErrEmptyPassword = errors.New("auth: kata sandi tidak boleh kosong")

// HashPassword menghasilkan hash PBKDF2 ber-salt dengan format self-describing
// "pbkdf2_sha256$<iter>$<b64salt>$<b64dk>". Aman untuk disimpan di store.
func HashPassword(pw string) (string, error) {
	if pw == "" {
		return "", ErrEmptyPassword
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: baca entropi: %w", err)
	}
	dk, err := pbkdf2.Key(sha256.New, pw, salt, pbkdfIter, pbkdfKeyLen)
	if err != nil {
		return "", fmt.Errorf("auth: derivasi kunci: %w", err)
	}
	return fmt.Sprintf("%s$%d$%s$%s", hashPrefix, pbkdfIter,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(dk)), nil
}

// VerifyPassword membandingkan pw dengan hash secara waktu-tetap. Mengembalikan
// false bila hash rusak/format tak dikenal atau kata sandi tak cocok.
func VerifyPassword(hash, pw string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 4 || parts[0] != hashPrefix {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter <= 0 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(want) == 0 {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, pw, salt, iter, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}
