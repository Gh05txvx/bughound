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
	tok, err := kr.Encrypt([]byte("api-key-rahasia-123"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok, "v1:"+kr.ActiveID()+":") {
		t.Errorf("format token salah: %s", tok)
	}
	if strings.Contains(tok, "api-key-rahasia-123") {
		t.Fatal("plaintext bocor ke token terenkripsi")
	}
	pt, err := kr.Decrypt(tok)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "api-key-rahasia-123" {
		t.Errorf("round-trip gagal: %q", pt)
	}
}

func TestDecryptTamperedFails(t *testing.T) {
	kr := mustKeyring(t)
	tok, _ := kr.Encrypt([]byte("x"))
	b := []byte(tok)
	i := strings.LastIndexByte(tok, ':') + 1 // awal base64
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	if _, err := kr.Decrypt(string(b)); err == nil {
		t.Fatal("ciphertext yang diubah harus gagal didekripsi (authenticated)")
	}
}

func TestRotationKeepsOldDecryptable(t *testing.T) {
	k1, _ := NewRandomKey()
	kr := NewKeyring(k1)
	oldTok, _ := kr.Encrypt([]byte("lama"))

	k2, _ := NewRandomKey()
	kr.Rotate(k2)

	// Token lama masih bisa didekripsi (kunci lama disimpan).
	pt, err := kr.Decrypt(oldTok)
	if err != nil || string(pt) != "lama" {
		t.Fatalf("token lama harus tetap terbaca: %q %v", pt, err)
	}
	// Token baru memakai kunci aktif k2.
	newTok, _ := kr.Encrypt([]byte("baru"))
	if !strings.Contains(newTok, k2.ID()) {
		t.Error("token baru harus memakai id kunci aktif")
	}
}

func TestDecryptUnknownKey(t *testing.T) {
	k1, _ := NewRandomKey()
	tok, _ := NewKeyring(k1).Encrypt([]byte("x"))
	k2, _ := NewRandomKey()
	if _, err := NewKeyring(k2).Decrypt(tok); err != ErrNoKey {
		t.Errorf("keyring tanpa kunci token harus ErrNoKey, dapat %v", err)
	}
}

func TestSecretRedaction(t *testing.T) {
	s := NewSecret([]byte("topsecret"))
	if s.String() != "[REDACTED]" {
		t.Error("String harus redaksi")
	}
	if b, _ := json.Marshal(s); strings.Contains(string(b), "topsecret") {
		t.Errorf("JSON membocorkan secret: %s", b)
	}
	if out := fmt.Sprintf("%v|%#v|%s", s, s, s); strings.Contains(out, "topsecret") {
		t.Errorf("format membocorkan secret: %s", out)
	}
	if string(s.Reveal()) != "topsecret" {
		t.Error("Reveal harus mengembalikan nilai asli")
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
		t.Errorf("env: src=%s id=%s (ingin %s)", src, kr.ActiveID(), k.ID())
	}
}

func TestLoadKeyringFileGenerateThenReuse(t *testing.T) {
	t.Setenv(EnvKey, "") // pastikan env kosong
	path := filepath.Join(t.TempDir(), "master.key")

	kr1, src1, err := LoadKeyring(path)
	if err != nil {
		t.Fatal(err)
	}
	if src1 != SourceGenerated {
		t.Errorf("pertama kali harus generated, dapat %s", src1)
	}
	kr2, src2, err := LoadKeyring(path)
	if err != nil {
		t.Fatal(err)
	}
	if src2 != SourceFile {
		t.Errorf("kedua kali harus dari file, dapat %s", src2)
	}
	if kr1.ActiveID() != kr2.ActiveID() {
		t.Error("kunci harus sama setelah dibaca ulang dari file")
	}
}

func TestLoadKeyringEphemeral(t *testing.T) {
	t.Setenv(EnvKey, "")
	_, src, err := LoadKeyring("")
	if err != nil {
		t.Fatal(err)
	}
	if src != SourceEphemeral {
		t.Errorf("tanpa env & path harus ephemeral, dapat %s", src)
	}
}

// Key & Keyring tak boleh membocorkan byte kunci lewat fmt. fmt melewati
// String() untuk field unexported, jadi guard dipasang di tipe Key/Keyring
// sendiri (bukan sekadar membungkus material dalam Secret).
func TestKeyKeyringRedactInFmt(t *testing.T) {
	raw := []byte(strings.Repeat("z", KeySize)) // 'z' = 0x7a -> "122" desimal / "0x7a" di %#v
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
			t.Errorf("fmt membocorkan byte kunci: %q", s)
		}
		if !strings.Contains(s, k.ID()) {
			t.Errorf("fmt harus menampilkan key-id, bukan byte: %q", s)
		}
	}
}
