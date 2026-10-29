package store

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"bughound/internal/finding"
	"bughound/internal/payload"
)

// Mem adalah Store in-memory yang aman dipakai konkuren. Dipakai untuk unit
// test dan untuk alur mock (E2E) sehingga tidak pernah menyentuh disk/jaringan.
type Mem struct {
	mu   sync.RWMutex
	now  func() time.Time
	byID map[string]*finding.Finding
	// primary: program -> dedup_key -> id temuan utama.
	primary  map[string]map[string]string
	programs map[string]*Program
	users    map[string]*User

	// Bank Payload (BH-SPEC-PAYLOAD): katalog in-memory, diganti utuh saat refresh.
	catalog        []payload.Entry
	catalogSources []payload.SourceInfo
	catalogBuiltAt time.Time
}

// NewMem membuat store in-memory kosong.
func NewMem() *Mem {
	return &Mem{
		now:      time.Now,
		byID:     map[string]*finding.Finding{},
		primary:  map[string]map[string]string{},
		programs: map[string]*Program{},
		users:    map[string]*User{},
	}
}

// SaveProgram: lihat Store.SaveProgram.
func (m *Mem) SaveProgram(ctx context.Context, p Program) error {
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("store: nama program wajib")
	}
	p.UpdatedAt = m.now().UTC()
	p.InScope = append([]string(nil), p.InScope...)
	p.OutScope = append([]string(nil), p.OutScope...)
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := p
	m.programs[p.Name] = &cp
	return nil
}

// GetProgram: lihat Store.GetProgram.
func (m *Mem) GetProgram(ctx context.Context, name string) (*Program, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.programs[name]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneProgram(p), nil
}

// ListPrograms: lihat Store.ListPrograms.
func (m *Mem) ListPrograms(ctx context.Context) ([]*Program, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Program, 0, len(m.programs))
	for _, p := range m.programs {
		out = append(out, cloneProgram(p))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func cloneProgram(p *Program) *Program {
	cp := *p
	cp.InScope = append([]string(nil), p.InScope...)
	cp.OutScope = append([]string(nil), p.OutScope...)
	return &cp
}

// Save: lihat Store.Save. Dedup ditegakkan di sini.
func (m *Mem) Save(ctx context.Context, f *finding.Finding) (SaveResult, error) {
	if err := prepare(f, m.now()); err != nil {
		return SaveResult{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	prog := m.primary[f.Program]
	if prog == nil {
		prog = map[string]string{}
		m.primary[f.Program] = prog
	}

	res := SaveResult{ID: f.ID}
	if primaryID, ok := prog[f.DedupKey]; ok {
		if primaryID != f.ID {
			f.Status = finding.StatusDuplicate
			f.DuplicateOf = primaryID
			res.Deduplicated = true
			res.PrimaryID = primaryID
		}
	} else {
		prog[f.DedupKey] = f.ID // temuan utama pertama untuk dedup_key ini
	}

	m.byID[f.ID] = clone(f)
	return res, nil
}

// Get: lihat Store.Get.
func (m *Mem) Get(ctx context.Context, id string) (*finding.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	f, ok := m.byID[id]
	if !ok {
		return nil, ErrNotFound
	}
	return clone(f), nil
}

// List: lihat Store.List.
func (m *Mem) List(ctx context.Context, q Query) ([]*finding.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	includeDup := q.IncludeDuplicates || containsStatus(q.Statuses, finding.StatusDuplicate)

	var out []*finding.Finding
	for _, f := range m.byID {
		if q.Program != "" && f.Program != q.Program {
			continue
		}
		if q.RunID != "" && f.RunID != q.RunID {
			continue
		}
		if f.Status == finding.StatusDuplicate && !includeDup {
			continue
		}
		if len(q.Statuses) > 0 && !containsStatus(q.Statuses, f.Status) {
			continue
		}
		if len(q.Severities) > 0 && !containsSeverity(q.Severities, f.Severity) {
			continue
		}
		if len(q.Types) > 0 && !containsString(q.Types, f.Type) {
			continue
		}
		out = append(out, clone(f))
	}

	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := severityRank(out[i].Severity), severityRank(out[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return out[i].CreatedAt.Time.After(out[j].CreatedAt.Time)
	})
	return out, nil
}

// Programs: lihat Store.Programs.
func (m *Mem) Programs(ctx context.Context) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	set := map[string]bool{}
	for _, f := range m.byID {
		set[f.Program] = true
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}

// SetStatus: lihat Store.SetStatus.
func (m *Mem) SetStatus(ctx context.Context, id string, status finding.Status, verifiedBy string) error {
	if !status.Valid() {
		return fmt.Errorf("store: status tidak sah: %q", status)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.byID[id]
	if !ok {
		return ErrNotFound
	}
	if status == finding.StatusDuplicate && strings.TrimSpace(f.DuplicateOf) == "" {
		return fmt.Errorf("store: status duplicate hanya lewat jalur dedup (duplicate_of kosong)")
	}
	f.Status = status
	if verifiedBy != "" {
		f.VerifiedBy = verifiedBy
	}
	now := finding.NewTime(m.now())
	f.UpdatedAt = &now
	return nil
}

// ---- UserStore (RBAC) ----

// CreateUser: lihat UserStore.CreateUser.
func (m *Mem) CreateUser(ctx context.Context, u User) error {
	if strings.TrimSpace(u.Username) == "" {
		return fmt.Errorf("store: username wajib")
	}
	if u.Created.IsZero() {
		u.Created = m.now().UTC()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[u.Username]; ok {
		return ErrUserExists
	}
	cp := u
	m.users[u.Username] = &cp
	return nil
}

// GetUser: lihat UserStore.GetUser.
func (m *Mem) GetUser(ctx context.Context, username string) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.users[username]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *u
	return &cp, nil
}

// ListUsers: lihat UserStore.ListUsers.
func (m *Mem) ListUsers(ctx context.Context) ([]*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*User, 0, len(m.users))
	for _, u := range m.users {
		cp := *u
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out, nil
}

// DeleteUser: lihat UserStore.DeleteUser.
func (m *Mem) DeleteUser(ctx context.Context, username string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[username]; !ok {
		return ErrNotFound
	}
	delete(m.users, username)
	return nil
}

// SetPassword: lihat UserStore.SetPassword.
func (m *Mem) SetPassword(ctx context.Context, username, passHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[username]
	if !ok {
		return ErrNotFound
	}
	u.PassHash = passHash
	return nil
}

// CountUsers: lihat UserStore.CountUsers.
func (m *Mem) CountUsers(ctx context.Context) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.users), nil
}

// Close no-op.
func (m *Mem) Close() error { return nil }
