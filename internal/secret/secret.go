// Package secret encrypts secrets at rest and manages their keys (binding
// bughound principle: "secrets are encrypted and isolated; they never leak to
// logs, responses or reports, and are never committed").
//
// Encryption: AES-256-GCM (authenticated). Each secret is stored as a token
// "v1:<key-id>:<base64(nonce|ciphertext)>"; the key-id binds the ciphertext to
// a key (so rotation can keep old keys for decryption) and is used as AAD so a
// changed key-id is detected.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// KeySize is the key size (AES-256).
const KeySize = 32

// ErrNoKey is returned when a token refers to a key-id that is not in the keyring.
var ErrNoKey = errors.New("secret: no key for the token's key-id (the old key is needed to decrypt)")

// Key is a 32-byte symmetric key with its derived id (one-way, it does not leak
// the key). The material is wrapped in a Secret; String/GoString redact (fmt
// skips String() for unexported fields, so the guard is on Key itself).
type Key struct {
	id  string
	mat Secret
}

// NewRandomKey creates a random key.
func NewRandomKey() (Key, error) {
	b := make([]byte, KeySize)
	if _, err := rand.Read(b); err != nil {
		return Key{}, fmt.Errorf("secret: cannot create key: %w", err)
	}
	return KeyFromBytes(b)
}

// KeyFromBytes wraps 32 bytes into a Key.
func KeyFromBytes(b []byte) (Key, error) {
	if len(b) != KeySize {
		return Key{}, fmt.Errorf("secret: key must be %d bytes, got %d", KeySize, len(b))
	}
	sum := sha256.Sum256(b)
	return Key{id: hex.EncodeToString(sum[:4]), mat: NewSecret(b)}, nil
}

// ID returns the key id (8 hex chars derived from a hash, not the key itself).
func (k Key) ID() string { return k.id }

// Base64 returns the encoded key (to be stored in the 0600 key file).
func (k Key) Base64() string { return base64.StdEncoding.EncodeToString(k.mat.Reveal()) }

// String and GoString redact: a Key never prints its bytes, only its id.
func (k Key) String() string   { return "Key(" + k.id + ")" }
func (k Key) GoString() string { return "secret.Key(" + k.id + ")" }

// Keyring holds the active key (for encryption) and old keys (for decryption
// during rotation).
type Keyring struct {
	active Key
	all    map[string]Key
}

// String and GoString redact: a Keyring never prints key bytes.
func (r *Keyring) String() string {
	return fmt.Sprintf("Keyring(active=%s, keys=%d)", r.active.id, len(r.all))
}
func (r *Keyring) GoString() string { return r.String() }

// NewKeyring creates a keyring with one active key.
func NewKeyring(active Key) *Keyring {
	return &Keyring{active: active, all: map[string]Key{active.ID(): active}}
}

// ActiveID returns the id of the active key.
func (r *Keyring) ActiveID() string { return r.active.ID() }

// Active returns the active key.
func (r *Keyring) Active() Key { return r.active }

// AllKeys returns every key (active first). It is used for persistence during
// rotation, so the old keys stay saved until re-encryption is done.
func (r *Keyring) AllKeys() []Key {
	out := []Key{r.active}
	for id, k := range r.all {
		if id != r.active.ID() {
			out = append(out, k)
		}
	}
	return out
}

// AddRetired adds an old key so old tokens can still be decrypted.
func (r *Keyring) AddRetired(k Key) { r.all[k.ID()] = k }

// Rotate makes newActive the active key; the old key is kept to decrypt tokens
// that have not been re-encrypted yet.
func (r *Keyring) Rotate(newActive Key) {
	r.all[newActive.ID()] = newActive
	r.active = newActive
}

// Subkey derives a purpose-specific key from the active key (e.g. for the audit
// trail HMAC) without exposing the master key itself.
func (r *Keyring) Subkey(label string) []byte {
	h := sha256.New()
	h.Write(r.active.mat.Reveal())
	h.Write([]byte(label))
	return h.Sum(nil)
}

// Encrypt encrypts plaintext with the active key.
func (r *Keyring) Encrypt(plaintext []byte) (string, error) {
	gcm, err := newGCM(r.active)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("secret: nonce failed: %w", err)
	}
	ct := gcm.Seal(nil, nonce, plaintext, []byte(r.active.ID()))
	blob := append(append([]byte(nil), nonce...), ct...)
	return "v1:" + r.active.ID() + ":" + base64.StdEncoding.EncodeToString(blob), nil
}

// Decrypt decrypts a token, picking the key by the key-id in the token.
func (r *Keyring) Decrypt(token string) ([]byte, error) {
	keyID, blob, err := parseToken(token)
	if err != nil {
		return nil, err
	}
	k, ok := r.all[keyID]
	if !ok {
		return nil, ErrNoKey
	}
	gcm, err := newGCM(k)
	if err != nil {
		return nil, err
	}
	if len(blob) < gcm.NonceSize() {
		return nil, errors.New("secret: ciphertext too short")
	}
	nonce, ct := blob[:gcm.NonceSize()], blob[gcm.NonceSize():]
	pt, err := gcm.Open(nil, nonce, ct, []byte(keyID))
	if err != nil {
		return nil, fmt.Errorf("secret: decryption failed (ciphertext and key do not match, or it was altered): %w", err)
	}
	return pt, nil
}

func newGCM(k Key) (cipher.AEAD, error) {
	block, err := aes.NewCipher(k.mat.Reveal())
	if err != nil {
		return nil, fmt.Errorf("secret: cipher: %w", err)
	}
	return cipher.NewGCM(block)
}

func parseToken(token string) (keyID string, blob []byte, err error) {
	parts := strings.SplitN(token, ":", 3)
	if len(parts) != 3 || parts[0] != "v1" {
		return "", nil, errors.New("secret: unknown token format")
	}
	blob, err = base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return "", nil, fmt.Errorf("secret: token base64 is corrupt: %w", err)
	}
	return parts[1], blob, nil
}

// Secret wraps a secret value so it does not leak by accident into
// logs/JSON/formatting. The value can only be read through Reveal().
type Secret struct{ v []byte }

// NewSecret wraps a value.
func NewSecret(v []byte) Secret { return Secret{v: append([]byte(nil), v...)} }

// Reveal returns the original value (the caller is responsible for not leaking it).
func (s Secret) Reveal() []byte { return s.v }

func (Secret) String() string               { return "[REDACTED]" }
func (Secret) GoString() string             { return "[REDACTED]" }
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"[REDACTED]"`), nil }
func (Secret) MarshalText() ([]byte, error) { return []byte("[REDACTED]"), nil }
