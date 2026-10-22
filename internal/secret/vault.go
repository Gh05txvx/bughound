package secret

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

// ErrSecretNotFound dikembalikan bila secret tak ada.
var ErrSecretNotFound = errors.New("secret: tidak ditemukan")

// Meta adalah metadata secret TANPA nilainya — aman untuk ditampilkan/di-log.
type Meta struct {
	Scope     string
	Name      string
	KeyID     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Vault menyimpan secret terenkripsi, terisolasi dari temuan. Nilai hanya bisa
// diambil lewat Reveal; List/Meta tidak pernah memuat nilai.
type Vault interface {
	Put(ctx context.Context, scope, name string, value []byte) error
	Reveal(ctx context.Context, scope, name string) ([]byte, error)
	List(ctx context.Context, scope string) ([]Meta, error)
	Delete(ctx context.Context, scope, name string) error
	Rotate(ctx context.Context) (int, error) // re-enkripsi semua ke kunci aktif
	// SetRevealHook memasang callback yang dipanggil tiap Reveal BERHASIL,
	// dengan scope+nama (TANPA nilai) — untuk mencatat akses secret ke audit.
	SetRevealHook(func(scope, name string))
	Close() error
}

func normScope(s string) string {
	if s = strings.TrimSpace(s); s != "" {
		return s
	}
	return "global"
}

type record struct {
	token     string
	keyID     string
	createdAt time.Time
	updatedAt time.Time
}

// MemVault adalah Vault in-memory (test / ephemeral).
type MemVault struct {
	kr       *Keyring
	now      func() time.Time
	onReveal func(scope, name string)
	mu       sync.RWMutex
	m        map[string]map[string]*record
}

// SetRevealHook: lihat Vault.SetRevealHook.
func (v *MemVault) SetRevealHook(fn func(scope, name string)) { v.onReveal = fn }

// NewMemVault membuat vault in-memory dengan keyring kr.
func NewMemVault(kr *Keyring) *MemVault {
	return &MemVault{kr: kr, now: time.Now, m: map[string]map[string]*record{}}
}

func (v *MemVault) Put(ctx context.Context, scope, name string, value []byte) error {
	if name = strings.TrimSpace(name); name == "" {
		return errors.New("secret: nama wajib")
	}
	token, err := v.kr.Encrypt(value)
	if err != nil {
		return err
	}
	scope = normScope(scope)
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.m[scope] == nil {
		v.m[scope] = map[string]*record{}
	}
	now := v.now().UTC()
	r := v.m[scope][name]
	if r == nil {
		r = &record{createdAt: now}
	}
	r.token, r.keyID, r.updatedAt = token, v.kr.ActiveID(), now
	v.m[scope][name] = r
	return nil
}

func (v *MemVault) Reveal(ctx context.Context, scope, name string) ([]byte, error) {
	scope = normScope(scope)
	v.mu.RLock()
	r := lookup(v.m, scope, name)
	v.mu.RUnlock()
	if r == nil {
		return nil, ErrSecretNotFound
	}
	pt, err := v.kr.Decrypt(r.token)
	if err == nil && v.onReveal != nil {
		v.onReveal(scope, name)
	}
	return pt, err
}

func (v *MemVault) List(ctx context.Context, scope string) ([]Meta, error) {
	scope = normScope(scope)
	v.mu.RLock()
	defer v.mu.RUnlock()
	var out []Meta
	for name, r := range v.m[scope] {
		out = append(out, Meta{Scope: scope, Name: name, KeyID: r.keyID, CreatedAt: r.createdAt, UpdatedAt: r.updatedAt})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (v *MemVault) Delete(ctx context.Context, scope, name string) error {
	scope = normScope(scope)
	v.mu.Lock()
	defer v.mu.Unlock()
	if lookup(v.m, scope, name) == nil {
		return ErrSecretNotFound
	}
	delete(v.m[scope], name)
	return nil
}

func (v *MemVault) Rotate(ctx context.Context) (int, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	n := 0
	for _, byName := range v.m {
		for _, r := range byName {
			pt, err := v.kr.Decrypt(r.token)
			if err != nil {
				return n, err
			}
			token, err := v.kr.Encrypt(pt)
			if err != nil {
				return n, err
			}
			r.token, r.keyID, r.updatedAt = token, v.kr.ActiveID(), v.now().UTC()
			n++
		}
	}
	return n, nil
}

func (v *MemVault) Close() error { return nil }

func lookup(m map[string]map[string]*record, scope, name string) *record {
	if m[scope] == nil {
		return nil
	}
	return m[scope][name]
}
