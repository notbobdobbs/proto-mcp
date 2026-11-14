//go:build !darwin

package store

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/just-an-oldsalt/proto-mcp/internal/secret"
)

// loadStoreKey returns the 32-byte mirror key for non-macOS builds.
//
// Production proto-mcp is macOS, and there the key lives in the
// Keychain (key_darwin.go), not next to the database. This file key
// exists so `go test` on Linux can seal the same way without a
// Keychain. It is not a substitute for the Keychain: anyone who can
// read the directory can read the key.
func loadStoreKey(dir string) (secret.Secret, error) {
	path := filepath.Join(dir, "store.key")
	if b, err := os.ReadFile(path); err == nil {
		if len(b) != 32 {
			return secret.Secret{}, fmt.Errorf("store: %s must be 32 bytes", path)
		}
		return secret.New(b), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return secret.Secret{}, err
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return secret.Secret{}, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return loadStoreKey(dir)
	}
	if err != nil {
		return secret.Secret{}, err
	}
	_, werr := f.Write(key)
	cerr := f.Close()
	if werr != nil {
		return secret.Secret{}, werr
	}
	if cerr != nil {
		return secret.Secret{}, cerr
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return secret.Secret{}, err
	}
	return secret.New(key), nil
}
