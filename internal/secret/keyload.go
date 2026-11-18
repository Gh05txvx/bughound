package secret

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

// EnvKey is the name of the environment variable for the master key (std base64, 32 bytes).
const EnvKey = "BUGHOUND_MASTER_KEY"

// KeySource says where the master key came from (for logs; never the value).
type KeySource string

const (
	SourceEnv       KeySource = "env"       // from BUGHOUND_MASTER_KEY
	SourceFile      KeySource = "file"      // read from the key file
	SourceGenerated KeySource = "generated" // newly created (the file is written when a path is given)
	SourceEphemeral KeySource = "ephemeral" // newly created, not persisted (dev)
)

// LoadKeyring loads the master key in this order of priority:
//
//  1. env BUGHOUND_MASTER_KEY (base64, 32 bytes); keyPath is ignored;
//  2. the keyPath file (base64) when it exists;
//  3. otherwise a random key is created: when keyPath is given it is written
//     with mode 0600 and used (generated); when keyPath is empty an ephemeral
//     key is used and not persisted.
//
// The key is never committed: git ignores the key file (see .gitignore).
// Note: on Windows the 0600 mode bits are best effort (ACLs work differently).
func LoadKeyring(keyPath string) (*Keyring, KeySource, error) {
	if env := strings.TrimSpace(os.Getenv(EnvKey)); env != "" {
		b, err := base64.StdEncoding.DecodeString(env)
		if err != nil {
			return nil, "", fmt.Errorf("secret: %s is not valid base64: %w", EnvKey, err)
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
				return nil, "", fmt.Errorf("secret: key file %q is corrupt: %w", keyPath, perr)
			}
			if len(keys) == 0 {
				return nil, "", fmt.Errorf("secret: key file %q is empty", keyPath)
			}
			kr := NewKeyring(keys[0]) // the first line = the active key
			for _, k := range keys[1:] {
				kr.AddRetired(k) // the rest: old keys for decryption (rotation transition)
			}
			return kr, SourceFile, nil
		}
		k, err := NewRandomKey()
		if err != nil {
			return nil, "", err
		}
		if err := WriteKeyFile(keyPath, k); err != nil {
			return nil, "", fmt.Errorf("secret: cannot write key file %q: %w", keyPath, err)
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

// WriteKeyFile writes the keys (active first) to path, one base64 per line,
// mode 0600. The master key is never committed (see .gitignore *.key).
func WriteKeyFile(path string, keys ...Key) error {
	if len(keys) == 0 {
		return fmt.Errorf("secret: no key to write")
	}
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k.Base64())
		b.WriteByte('\n')
	}
	return os.WriteFile(path, []byte(b.String()), 0o600)
}
