package secret

import (
	"context"
	"path/filepath"
	"testing"
)

type vaultFactory struct {
	name string
	open func(t *testing.T, kr *Keyring) Vault
}

func factories() []vaultFactory {
	return []vaultFactory{
		{"mem", func(t *testing.T, kr *Keyring) Vault { return NewMemVault(kr) }},
		{"sqlite", func(t *testing.T, kr *Keyring) Vault {
			v, err := OpenSQLiteVault(filepath.Join(t.TempDir(), "v.db"), kr)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { v.Close() })
			return v
		}},
	}
}

func TestVaultPutRevealListDelete(t *testing.T) {
	for _, f := range factories() {
		t.Run(f.name, func(t *testing.T) {
			kr := mustKeyring(t)
			v := f.open(t, kr)
			ctx := context.Background()

			if err := v.Put(ctx, "progA", "engine-token", []byte("s3cr3t")); err != nil {
				t.Fatal(err)
			}
			got, err := v.Reveal(ctx, "progA", "engine-token")
			if err != nil || string(got) != "s3cr3t" {
				t.Fatalf("reveal failed: %q %v", got, err)
			}

			metas, err := v.List(ctx, "progA")
			if err != nil || len(metas) != 1 || metas[0].Name != "engine-token" {
				t.Fatalf("wrong list meta: %+v %v", metas, err)
			}
			if metas[0].KeyID != kr.ActiveID() {
				t.Errorf("key id meta=%s, want %s", metas[0].KeyID, kr.ActiveID())
			}

			// Scope isolation: another scope does not see it.
			if m, _ := v.List(ctx, "progB"); len(m) != 0 {
				t.Errorf("another scope must not see the secret; got %d", len(m))
			}
			if _, err := v.Reveal(ctx, "progA", "missing"); err != ErrSecretNotFound {
				t.Errorf("a missing secret must return ErrSecretNotFound, got %v", err)
			}

			if err := v.Delete(ctx, "progA", "engine-token"); err != nil {
				t.Fatal(err)
			}
			if _, err := v.Reveal(ctx, "progA", "engine-token"); err != ErrSecretNotFound {
				t.Error("after delete it must not be found")
			}
			if err := v.Delete(ctx, "progA", "engine-token"); err != ErrSecretNotFound {
				t.Error("deleting twice must return ErrSecretNotFound")
			}
		})
	}
}

func TestVaultRevealHookAudited(t *testing.T) {
	for _, f := range factories() {
		t.Run(f.name, func(t *testing.T) {
			kr := mustKeyring(t)
			v := f.open(t, kr)
			ctx := context.Background()
			v.Put(ctx, "progA", "token", []byte("top-secret"))

			var calls int
			var gotScope, gotName string
			v.SetRevealHook(func(scope, name string) {
				calls++
				gotScope, gotName = scope, name
			})

			if _, err := v.Reveal(ctx, "progA", "token"); err != nil {
				t.Fatal(err)
			}
			if calls != 1 || gotScope != "progA" || gotName != "token" {
				t.Errorf("hook reveal: calls=%d scope=%q name=%q", calls, gotScope, gotName)
			}
			// A failed Reveal (missing) must not fire the hook.
			v.Reveal(ctx, "progA", "missing")
			if calls != 1 {
				t.Errorf("the hook must not be called when the secret is missing; calls=%d", calls)
			}
		})
	}
}

func TestVaultRotate(t *testing.T) {
	for _, f := range factories() {
		t.Run(f.name, func(t *testing.T) {
			k1, _ := NewRandomKey()
			kr := NewKeyring(k1)
			v := f.open(t, kr)
			ctx := context.Background()

			v.Put(ctx, "g", "a", []byte("AAA"))
			v.Put(ctx, "g", "b", []byte("BBB"))

			k2, _ := NewRandomKey()
			kr.Rotate(k2)
			n, err := v.Rotate(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if n != 2 {
				t.Errorf("must re-encrypt 2 secrets, got %d", n)
			}
			// The values are intact, now under the new key.
			if a, _ := v.Reveal(ctx, "g", "a"); string(a) != "AAA" {
				t.Error("the value must be intact after rotation")
			}
			metas, _ := v.List(ctx, "g")
			for _, m := range metas {
				if m.KeyID != k2.ID() {
					t.Errorf("after rotation the key id must be %s, got %s", k2.ID(), m.KeyID)
				}
			}
		})
	}
}
