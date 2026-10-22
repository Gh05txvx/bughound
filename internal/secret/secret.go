// Package secret mengenkripsi secret saat disimpan dan mengelola kuncinya
// (prinsip mengikat bughound: "secret terenkripsi dan terisolasi; tidak pernah
// bocor ke log, respons, atau report, dan tidak pernah di-commit").
//
// Enkripsi: AES-256-GCM (authenticated). Setiap secret disimpan sebagai token
// "v1:<key-id>:<base64(nonce|ciphertext)>"; key-id mengikat ciphertext ke kunci
// (jadi rotasi bisa menyimpan kunci lama untuk dekripsi) dan dipakai sebagai AAD
// agar perubahan key-id terdeteksi.
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

// KeySize adalah ukuran kunci (AES-256).
const KeySize = 32

// ErrNoKey dikembalikan bila token merujuk key-id yang tak ada di keyring.
var ErrNoKey = errors.New("secret: tidak ada kunci untuk key-id token (perlu kunci lama untuk dekripsi)")

// Key adalah kunci simetris 32-byte beserta id turunannya (one-way, tidak
// membocorkan kunci).
type Key struct {
	id    string
	bytes []byte
}

// NewRandomKey membuat kunci acak.
func NewRandomKey() (Key, error) {
	b := make([]byte, KeySize)
	if _, err := rand.Read(b); err != nil {
		return Key{}, fmt.Errorf("secret: gagal membuat kunci: %w", err)
	}
	return KeyFromBytes(b)
}

// KeyFromBytes membungkus 32 byte menjadi Key.
func KeyFromBytes(b []byte) (Key, error) {
	if len(b) != KeySize {
		return Key{}, fmt.Errorf("secret: kunci harus %d byte, dapat %d", KeySize, len(b))
	}
	sum := sha256.Sum256(b)
	return Key{id: hex.EncodeToString(sum[:4]), bytes: append([]byte(nil), b...)}, nil
}

// ID mengembalikan id kunci (8 hex, turunan hash — bukan kunci itu sendiri).
func (k Key) ID() string { return k.id }

// Base64 mengembalikan kunci ter-encode (untuk disimpan ke file kunci 0600).
func (k Key) Base64() string { return base64.StdEncoding.EncodeToString(k.bytes) }

// Keyring menyimpan kunci aktif (untuk enkripsi) dan kunci lama (untuk dekripsi
// saat rotasi).
type Keyring struct {
	active Key
	all    map[string]Key
}

// NewKeyring membuat keyring dengan satu kunci aktif.
func NewKeyring(active Key) *Keyring {
	return &Keyring{active: active, all: map[string]Key{active.ID(): active}}
}

// ActiveID mengembalikan id kunci aktif.
func (r *Keyring) ActiveID() string { return r.active.ID() }

// AddRetired menambah kunci lama agar token lama tetap bisa didekripsi.
func (r *Keyring) AddRetired(k Key) { r.all[k.ID()] = k }

// Rotate menjadikan newActive kunci aktif; kunci lama tetap disimpan untuk
// dekripsi token yang belum di-re-enkripsi.
func (r *Keyring) Rotate(newActive Key) {
	r.all[newActive.ID()] = newActive
	r.active = newActive
}

// Encrypt mengenkripsi plaintext dengan kunci aktif.
func (r *Keyring) Encrypt(plaintext []byte) (string, error) {
	gcm, err := newGCM(r.active)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("secret: gagal nonce: %w", err)
	}
	ct := gcm.Seal(nil, nonce, plaintext, []byte(r.active.ID()))
	blob := append(append([]byte(nil), nonce...), ct...)
	return "v1:" + r.active.ID() + ":" + base64.StdEncoding.EncodeToString(blob), nil
}

// Decrypt mendekripsi token, memilih kunci sesuai key-id di token.
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
		return nil, errors.New("secret: ciphertext terlalu pendek")
	}
	nonce, ct := blob[:gcm.NonceSize()], blob[gcm.NonceSize():]
	pt, err := gcm.Open(nil, nonce, ct, []byte(keyID))
	if err != nil {
		return nil, fmt.Errorf("secret: dekripsi gagal (ciphertext/kunci tidak cocok atau diubah): %w", err)
	}
	return pt, nil
}

func newGCM(k Key) (cipher.AEAD, error) {
	block, err := aes.NewCipher(k.bytes)
	if err != nil {
		return nil, fmt.Errorf("secret: cipher: %w", err)
	}
	return cipher.NewGCM(block)
}

func parseToken(token string) (keyID string, blob []byte, err error) {
	parts := strings.SplitN(token, ":", 3)
	if len(parts) != 3 || parts[0] != "v1" {
		return "", nil, errors.New("secret: format token tak dikenal")
	}
	blob, err = base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return "", nil, fmt.Errorf("secret: base64 token rusak: %w", err)
	}
	return parts[1], blob, nil
}

// Secret membungkus nilai rahasia agar tak sengaja bocor ke log/JSON/format.
// Nilai hanya bisa diambil lewat Reveal().
type Secret struct{ v []byte }

// NewSecret membungkus nilai.
func NewSecret(v []byte) Secret { return Secret{v: append([]byte(nil), v...)} }

// Reveal mengembalikan nilai asli (pemanggil bertanggung jawab tak membocorkan).
func (s Secret) Reveal() []byte { return s.v }

func (Secret) String() string                { return "[REDACTED]" }
func (Secret) GoString() string               { return "[REDACTED]" }
func (Secret) MarshalJSON() ([]byte, error)   { return []byte(`"[REDACTED]"`), nil }
func (Secret) MarshalText() ([]byte, error)   { return []byte("[REDACTED]"), nil }
