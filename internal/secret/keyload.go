package secret

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

// EnvKey adalah nama environment variable untuk kunci master (base64 std, 32 byte).
const EnvKey = "BUGHOUND_MASTER_KEY"

// KeySource menjelaskan dari mana kunci master berasal (untuk log, bukan nilai).
type KeySource string

const (
	SourceEnv       KeySource = "env"       // dari BUGHOUND_MASTER_KEY
	SourceFile      KeySource = "file"      // dibaca dari file kunci
	SourceGenerated KeySource = "generated" // dibuat baru (file ditulis bila ada path)
	SourceEphemeral KeySource = "ephemeral" // dibuat baru, tidak dipersist (dev)
)

// LoadKeyring memuat kunci master dengan prioritas:
//
//  1. env BUGHOUND_MASTER_KEY (base64 32 byte) — keyPath diabaikan;
//  2. file keyPath (base64) bila ada;
//  3. selain itu buat kunci acak: bila keyPath diberikan, tulis 0600 lalu pakai
//     (generated); bila keyPath kosong, pakai kunci ephemeral yang tak dipersist.
//
// Kunci tidak pernah di-commit: file kunci diabaikan git (lihat .gitignore).
// Catatan: di Windows, bit mode 0600 bersifat best-effort (ACL berbeda).
func LoadKeyring(keyPath string) (*Keyring, KeySource, error) {
	if env := strings.TrimSpace(os.Getenv(EnvKey)); env != "" {
		b, err := base64.StdEncoding.DecodeString(env)
		if err != nil {
			return nil, "", fmt.Errorf("secret: %s bukan base64 valid: %w", EnvKey, err)
		}
		k, err := KeyFromBytes(b)
		if err != nil {
			return nil, "", err
		}
		return NewKeyring(k), SourceEnv, nil
	}

	if keyPath != "" {
		if data, err := os.ReadFile(keyPath); err == nil {
			keys, perr := parseKeyLines(string(data))
			if perr != nil {
				return nil, "", fmt.Errorf("secret: file kunci %q rusak: %w", keyPath, perr)
			}
			if len(keys) == 0 {
				return nil, "", fmt.Errorf("secret: file kunci %q kosong", keyPath)
			}
			kr := NewKeyring(keys[0]) // baris pertama = kunci aktif
			for _, k := range keys[1:] {
				kr.AddRetired(k) // sisanya: kunci lama untuk dekripsi (transisi rotasi)
			}
			return kr, SourceFile, nil
		}
		k, err := NewRandomKey()
		if err != nil {
			return nil, "", err
		}
		if err := WriteKeyFile(keyPath, k); err != nil {
			return nil, "", fmt.Errorf("secret: gagal menulis file kunci %q: %w", keyPath, err)
		}
		return NewKeyring(k), SourceGenerated, nil
	}

	k, err := NewRandomKey()
	if err != nil {
		return nil, "", err
	}
	return NewKeyring(k), SourceEphemeral, nil
}

func parseKeyLines(data string) ([]Key, error) {
	var keys []Key
	for _, ln := range strings.Split(data, "\n") {
		if ln = strings.TrimSpace(ln); ln == "" {
			continue
		}
		b, err := base64.StdEncoding.DecodeString(ln)
		if err != nil {
			return nil, err
		}
		k, err := KeyFromBytes(b)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// WriteKeyFile menulis kunci (aktif lebih dulu) ke path, satu base64 per baris,
// mode 0600. Kunci master tidak pernah di-commit (lihat .gitignore *.key).
func WriteKeyFile(path string, keys ...Key) error {
	if len(keys) == 0 {
		return fmt.Errorf("secret: tak ada kunci untuk ditulis")
	}
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k.Base64())
		b.WriteByte('\n')
	}
	return os.WriteFile(path, []byte(b.String()), 0o600)
}
