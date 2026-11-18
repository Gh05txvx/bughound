// Package auth provides RBAC roles and password hashing for bughound.
//
// Hashing uses PBKDF2-HMAC-SHA256 from the standard library (crypto/pbkdf2,
// available since Go 1.24), so it adds no third-party dependency. Each hash has
// a random salt and a self-describing encoding (algorithm + iterations + salt),
// so the parameters can be raised without breaking old hashes. Verification
// uses a constant-time comparison. Raw passwords are never stored or logged.
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

// Role is an RBAC role. Privilege order: viewer < operator < admin.
//
//   - viewer   : read only (dashboard, findings, report, audit).
//   - operator : viewer + run scans, triage, manage programs, capture.
//   - admin    : operator + manage users.
type Role string

const (
	RoleAdmin    Role = "admin"
	RoleOperator Role = "operator"
	RoleViewer   Role = "viewer"
)

// Roles returns the known roles (used to fill the UI dropdown).
func Roles() []Role { return []Role{RoleAdmin, RoleOperator, RoleViewer} }

// Valid reports whether r is one of the known roles.
func (r Role) Valid() bool {
	switch r {
	case RoleAdmin, RoleOperator, RoleViewer:
		return true
	}
	return false
}

// CanRead: every valid role may read (viewer and up).
func CanRead(r Role) bool { return r.Valid() }

// CanWrite: operator and admin may change state (scan, triage, program, secret).
func CanWrite(r Role) bool { return r == RoleOperator || r == RoleAdmin }

// CanAdmin: admin only (user management).
func CanAdmin(r Role) bool { return r == RoleAdmin }

// PBKDF2 parameters. The iteration count is conservative for interactive login
// on a small server; it is stored in the hash, so it can be raised later.
const (
	pbkdfIter   = 210_000
	pbkdfKeyLen = 32
	saltLen     = 16
	hashPrefix  = "pbkdf2_sha256"
)

// ErrEmptyPassword is returned by HashPassword when the password is empty.
var ErrEmptyPassword = errors.New("auth: password must not be empty")

// HashPassword returns a salted PBKDF2 hash in the self-describing format
// "pbkdf2_sha256$<iter>$<b64salt>$<b64dk>". It is safe to keep in the store.
func HashPassword(pw string) (string, error) {
	if pw == "" {
		return "", ErrEmptyPassword
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: read entropy: %w", err)
	}
	dk, err := pbkdf2.Key(sha256.New, pw, salt, pbkdfIter, pbkdfKeyLen)
	if err != nil {
		return "", fmt.Errorf("auth: derive key: %w", err)
	}
	return fmt.Sprintf("%s$%d$%s$%s", hashPrefix, pbkdfIter,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(dk)), nil
}

// VerifyPassword compares pw with hash in constant time. It returns false when
// the hash is corrupt or in an unknown format, or when the password does not match.
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
