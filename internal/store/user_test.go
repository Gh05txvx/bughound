package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

// userStores returns one Mem and one SQLite (a temporary file) so the UserStore
// contract is tested identically on both implementations.
func userStores(t *testing.T) map[string]UserStore {
	t.Helper()
	sq, err := OpenSQLite(filepath.Join(t.TempDir(), "users.db"))
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	t.Cleanup(func() { sq.Close() })
	return map[string]UserStore{"mem": NewMem(), "sqlite": sq}
}

func TestUserStoreCRUD(t *testing.T) {
	ctx := context.Background()
	for name, us := range userStores(t) {
		t.Run(name, func(t *testing.T) {
			if n, _ := us.CountUsers(ctx); n != 0 {
				t.Fatalf("a new store must have 0 users, got %d", n)
			}
			if err := us.CreateUser(ctx, User{Username: "alice", Role: "admin", PassHash: "h1"}); err != nil {
				t.Fatalf("CreateUser: %v", err)
			}
			// Duplicates are rejected.
			if err := us.CreateUser(ctx, User{Username: "alice", Role: "viewer", PassHash: "h2"}); !errors.Is(err, ErrUserExists) {
				t.Fatalf("a duplicate username must be ErrUserExists, got %v", err)
			}
			if err := us.CreateUser(ctx, User{Username: "bob", Role: "operator", PassHash: "h3"}); err != nil {
				t.Fatalf("CreateUser bob: %v", err)
			}

			u, err := us.GetUser(ctx, "alice")
			if err != nil || u.Role != "admin" || u.PassHash != "h1" {
				t.Fatalf("GetUser alice = %+v, err=%v", u, err)
			}
			if u.Created.IsZero() {
				t.Error("Created must be filled in automatically")
			}

			if n, _ := us.CountUsers(ctx); n != 2 {
				t.Fatalf("want 2 user, got %d", n)
			}
			list, _ := us.ListUsers(ctx)
			if len(list) != 2 || list[0].Username != "alice" || list[1].Username != "bob" {
				t.Fatalf("wrong ListUsers order: %+v", list)
			}

			// SetPassword changes the hash.
			if err := us.SetPassword(ctx, "bob", "h3-new"); err != nil {
				t.Fatalf("SetPassword: %v", err)
			}
			if u, _ := us.GetUser(ctx, "bob"); u.PassHash != "h3-new" {
				t.Errorf("SetPassword was not saved: %q", u.PassHash)
			}

			// Delete.
			if err := us.DeleteUser(ctx, "bob"); err != nil {
				t.Fatalf("DeleteUser: %v", err)
			}
			if _, err := us.GetUser(ctx, "bob"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("a deleted user must be ErrNotFound, got %v", err)
			}
		})
	}
}

func TestUserStoreMissing(t *testing.T) {
	ctx := context.Background()
	for name, us := range userStores(t) {
		t.Run(name, func(t *testing.T) {
			if _, err := us.GetUser(ctx, "nope"); !errors.Is(err, ErrNotFound) {
				t.Errorf("GetUser on a missing user = %v, want ErrNotFound", err)
			}
			if err := us.DeleteUser(ctx, "nope"); !errors.Is(err, ErrNotFound) {
				t.Errorf("DeleteUser on a missing user = %v, want ErrNotFound", err)
			}
			if err := us.SetPassword(ctx, "nope", "x"); !errors.Is(err, ErrNotFound) {
				t.Errorf("SetPassword on a missing user = %v, want ErrNotFound", err)
			}
		})
	}
}
