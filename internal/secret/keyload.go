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
			b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
			if err != nil {
				return nil, "", fmt.Errorf("secret: file kunci %q rusak: %w", keyPath, err)
			}
			k, err := KeyFromBytes(b)
			if err != nil {
				return nil, "", err
			}
			return NewKeyring(k), SourceFile, nil
		}
		k, err := NewRandomKey()
		if err != nil {
			return nil, "", err
		}
		if err := os.WriteFile(keyPath, []byte(k.Base64()), 0o600); err != nil {
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
