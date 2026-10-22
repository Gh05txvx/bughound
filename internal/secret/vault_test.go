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
				t.Fatalf("reveal gagal: %q %v", got, err)
			}

			metas, err := v.List(ctx, "progA")
			if err != nil || len(metas) != 1 || metas[0].Name != "engine-token" {
				t.Fatalf("list meta salah: %+v %v", metas, err)
			}
			if metas[0].KeyID != kr.ActiveID() {
				t.Errorf("key id meta=%s, ingin %s", metas[0].KeyID, kr.ActiveID())
			}

			// Isolasi scope: scope lain tak melihatnya.
			if m, _ := v.List(ctx, "progB"); len(m) != 0 {
				t.Errorf("scope lain tak boleh melihat secret; dapat %d", len(m))
			}
			if _, err := v.Reveal(ctx, "progA", "tidak-ada"); err != ErrSecretNotFound {
				t.Errorf("secret tak ada harus ErrSecretNotFound, dapat %v", err)
			}

			if err := v.Delete(ctx, "progA", "engine-token"); err != nil {
				t.Fatal(err)
			}
			if _, err := v.Reveal(ctx, "progA", "engine-token"); err != ErrSecretNotFound {
				t.Error("setelah delete harus tak ditemukan")
			}
			if err := v.Delete(ctx, "progA", "engine-token"); err != ErrSecretNotFound {
				t.Error("delete dua kali harus ErrSecretNotFound")
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
				t.Errorf("harus re-enkripsi 2 secret, dapat %d", n)
			}
			// Nilai tetap utuh, kini di bawah kunci baru.
			if a, _ := v.Reveal(ctx, "g", "a"); string(a) != "AAA" {
				t.Error("nilai harus utuh setelah rotasi")
			}
			metas, _ := v.List(ctx, "g")
			for _, m := range metas {
				if m.KeyID != k2.ID() {
					t.Errorf("setelah rotasi key id harus %s, dapat %s", k2.ID(), m.KeyID)
				}
			}
		})
	}
}
