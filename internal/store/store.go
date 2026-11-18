// Package store stores findings in the Uniform Finding Schema (BH-SPEC-FINDING),
// organized per program and per run, and provides queries for triage and
// reports. Dedup is enforced by (program, dedup_key): the first finding for a
// dedup_key becomes the main one, and later occurrences are marked as
// duplicates with duplicate_of pointing at the main one.
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

// Store is the finding storage contract. Implementations (in-memory, SQLite)
// must enforce the same dedup.
type Store interface {
	// Save stores one finding. An empty ID/dedup_key/created_at is filled in
	// automatically. It reports whether the finding was recognized as a duplicate.
	Save(ctx context.Context, f *finding.Finding) (SaveResult, error)
	// Get gets one finding by id.
	Get(ctx context.Context, id string) (*finding.Finding, error)
	// List returns the findings matching Query, the most severe first.
	List(ctx context.Context, q Query) ([]*finding.Finding, error)
	// Programs returns the distinct names of programs that have stored findings.
	Programs(ctx context.Context) ([]string, error)
	// SaveProgram saves/updates a program's scope definition (persistent).
	SaveProgram(ctx context.Context, p Program) error
	// GetProgram gets a program definition; ErrNotFound when there is none.
	GetProgram(ctx context.Context, name string) (*Program, error)
	// ListPrograms returns every stored program, sorted by name.
	ListPrograms(ctx context.Context) ([]*Program, error)
	// DeleteProgram deletes a program's scope definition; ErrNotFound when there is
	// none. Only the program definition is deleted; findings and audit are NOT
	// touched (findings are work product, and the audit is append-only per the
	// security principles).
	DeleteProgram(ctx context.Context, name string) error
	// DeleteFindingsByProgram deletes ALL findings of a program (including its
	// dedup state) and returns how many were deleted. The program's scope
	// definition (SaveProgram) is NOT touched; that is managed separately through
	// DeleteProgram. The append-only audit is not touched either; the caller
	// records the deletion. A program without findings → 0, nil (not an error).
	DeleteFindingsByProgram(ctx context.Context, program string) (int, error)
	// SetStatus changes the triage status of a finding.
	SetStatus(ctx context.Context, id string, status finding.Status, verifiedBy string) error
	// UpdateContent updates the report narrative fields (description, impact,
	// reproduction) of a finding, filled in by the hunter during triage so the
	// draft report is complete (repro + impact). It does not touch
	// status/dedup/severity. ErrNotFound when the id does not exist.
	UpdateContent(ctx context.Context, id, description, impact string, reproduction []string) error
	// Close releases resources (a no-op for in-memory).
	Close() error
}

// SaveResult reports the result of saving one finding.
type SaveResult struct {
	ID           string
	Deduplicated bool
	PrimaryID    string // id of the main finding when Deduplicated
}

// Query filters the list of findings. Duplicates are hidden by default unless
// asked for explicitly (IncludeDuplicates, or Statuses containing "duplicate").
type Query struct {
	Program           string
	RunID             string
	Statuses          []finding.Status
	Severities        []finding.Severity
	Types             []string
	IncludeDuplicates bool
}

// ErrNotFound is returned by Get/SetStatus when the id does not exist.
var ErrNotFound = errors.New("store: finding not found")

// ErrUserExists is returned by CreateUser when the username is already taken.
var ErrUserExists = errors.New("store: username already exists")

// Program holds the scope definition of a bounty program (persistent).
type Program struct {
	Name      string
	InScope   []string
	OutScope  []string
	Preset    ScanPreset // per-program template selection preset (prefills the scan form)
	UpdatedAt time.Time
}

// ScanPreset is a stored template selection for a program; it prefills the scan
// form when the same program is chosen again. It only affects WHICH templates
// run (nuclei -tags/-severity) and the low-and-slow profile. It does NOT touch
// the scope guard, egress, rate limiter or secrets, so it is not a security
// control. An empty selection = all enabled templates (the default behaviour).
type ScanPreset struct {
	Tags      []string
	Severity  []string
	Stealth   bool
	APIRoutes bool // include the bundled API route wordlist (ffuf) in the scan
}

// User is an RBAC account (see internal/auth for roles and hashing). PassHash
// holds a salted PBKDF2 hash; the raw password is NEVER stored.
type User struct {
	Username string
	Role     string // "admin" | "operator" | "viewer" (auth.Role)
	PassHash string
	Created  time.Time
}

// UserStore manages RBAC accounts. Mem and SQLite both implement it, so a single
// store object provides findings and users.
type UserStore interface {
	// CreateUser saves a new user; ErrUserExists when the username already exists.
	CreateUser(ctx context.Context, u User) error
	// GetUser gets a user; ErrNotFound when there is none.
	GetUser(ctx context.Context, username string) (*User, error)
	// ListUsers returns every user, sorted by username.
	ListUsers(ctx context.Context) ([]*User, error)
	// DeleteUser deletes a user; ErrNotFound when there is none.
	DeleteUser(ctx context.Context, username string) error
	// SetPassword updates a user's password hash; ErrNotFound when there is none.
	SetPassword(ctx context.Context, username, passHash string) error
	// CountUsers returns the number of users (for bootstrapping the first admin).
	CountUsers(ctx context.Context) (int, error)
}

// prepare fills in the derived fields (id, schema_version, dedup_key,
// created_at) that are still empty, then validates the finding.
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

// newID generates a UUIDv4 without an external dependency.
func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("store: cannot generate id: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // varian RFC 4122
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// clone makes a deep copy so the store does not share state with the caller.
func clone(f *finding.Finding) *finding.Finding {
	b, _ := json.Marshal(f)
	var c finding.Finding
	_ = json.Unmarshal(b, &c)
	return &c
}

// severityRank: higher means more severe, for priority ordering.
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
