package secret

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func mustKeyring(t *testing.T) *Keyring {
	t.Helper()
	k, err := NewRandomKey()
	if err != nil {
		t.Fatal(err)
	}
	return NewKeyring(k)
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	kr := mustKeyring(t)
	tok, err := kr.Encrypt([]byte("api-key-secret-123"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok, "v1:"+kr.ActiveID()+":") {
		t.Errorf("wrong token format: %s", tok)
	}
	if strings.Contains(tok, "api-key-secret-123") {
		t.Fatal("plaintext leaked into the encrypted token")
	}
	pt, err := kr.Decrypt(tok)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "api-key-secret-123" {
		t.Errorf("round-trip failed: %q", pt)
	}
}

func TestDecryptTamperedFails(t *testing.T) {
	kr := mustKeyring(t)
	tok, _ := kr.Encrypt([]byte("x"))
	b := []byte(tok)
	i := strings.LastIndexByte(tok, ':') + 1 // start of the base64
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	if _, err := kr.Decrypt(string(b)); err == nil {
		t.Fatal("an altered ciphertext must fail to decrypt (authenticated)")
	}
}

func TestRotationKeepsOldDecryptable(t *testing.T) {
	k1, _ := NewRandomKey()
	kr := NewKeyring(k1)
	oldTok, _ := kr.Encrypt([]byte("old"))

	k2, _ := NewRandomKey()
	kr.Rotate(k2)

	// The old token can still be decrypted (the old key is kept).
	pt, err := kr.Decrypt(oldTok)
	if err != nil || string(pt) != "old" {
		t.Fatalf("the old token must still be readable: %q %v", pt, err)
	}
	// The new token uses the active key k2.
	newTok, _ := kr.Encrypt([]byte("new"))
	if !strings.Contains(newTok, k2.ID()) {
		t.Error("the new token must use the active key id")
	}
}

func TestDecryptUnknownKey(t *testing.T) {
	k1, _ := NewRandomKey()
	tok, _ := NewKeyring(k1).Encrypt([]byte("x"))
	k2, _ := NewRandomKey()
	if _, err := NewKeyring(k2).Decrypt(tok); err != ErrNoKey {
		t.Errorf("a keyring without the token's key must return ErrNoKey, got %v", err)
	}
}

func TestSecretRedaction(t *testing.T) {
	s := NewSecret([]byte("topsecret"))
	if s.String() != "[REDACTED]" {
		t.Error("String must redact")
	}
	if b, _ := json.Marshal(s); strings.Contains(string(b), "topsecret") {
		t.Errorf("JSON leaks the secret: %s", b)
	}
	if out := fmt.Sprintf("%v|%#v|%s", s, s, s); strings.Contains(out, "topsecret") {
		t.Errorf("formatting leaks the secret: %s", out)
	}
	if string(s.Reveal()) != "topsecret" {
		t.Error("Reveal must return the original value")
	}
}

func TestLoadKeyringEnv(t *testing.T) {
	k, _ := NewRandomKey()
	t.Setenv(EnvKey, k.Base64())
	kr, src, err := LoadKeyring("")
	if err != nil {
		t.Fatal(err)
	}
	if src != SourceEnv || kr.ActiveID() != k.ID() {
		t.Errorf("env: src=%s id=%s (want %s)", src, kr.ActiveID(), k.ID())
	}
}

func TestLoadKeyringFileGenerateThenReuse(t *testing.T) {
	t.Setenv(EnvKey, "") // make sure the env is empty
	path := filepath.Join(t.TempDir(), "master.key")

	kr1, src1, err := LoadKeyring(path)
	if err != nil {
		t.Fatal(err)
	}
	if src1 != SourceGenerated {
		t.Errorf("the first load must be generated, got %s", src1)
	}
	kr2, src2, err := LoadKeyring(path)
	if err != nil {
		t.Fatal(err)
	}
	if src2 != SourceFile {
		t.Errorf("the second load must come from the file, got %s", src2)
	}
	if kr1.ActiveID() != kr2.ActiveID() {
		t.Error("the key must be the same after it is read back from the file")
	}
}

func TestLoadKeyringEphemeral(t *testing.T) {
	t.Setenv(EnvKey, "")
	_, src, err := LoadKeyring("")
	if err != nil {
		t.Fatal(err)
	}
	if src != SourceEphemeral {
		t.Errorf("with no env and no path it must be ephemeral, got %s", src)
	}
}

// Key and Keyring must not leak key bytes through fmt. fmt skips String() for
// unexported fields, so the guard sits on the Key/Keyring types themselves
// (wrapping the material in a Secret is not enough).
func TestKeyKeyringRedactInFmt(t *testing.T) {
	raw := []byte(strings.Repeat("z", KeySize)) // 'z' = 0x7a -> "122" decimal / "0x7a" in %#v
	k, err := KeyFromBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	kr := NewKeyring(k)
	for _, s := range []string{
		fmt.Sprintf("%v", k), fmt.Sprintf("%+v", k), fmt.Sprintf("%#v", k),
		fmt.Sprintf("%v", kr), fmt.Sprintf("%+v", kr), fmt.Sprintf("%#v", kr),
	} {
		if strings.Contains(s, "122") || strings.Contains(s, "0x7a") {
			t.Errorf("fmt leaks key bytes: %q", s)
		}
		if !strings.Contains(s, k.ID()) {
			t.Errorf("fmt must show the key-id, not the bytes: %q", s)
		}
	}
}
