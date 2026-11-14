//go:build darwin

package store

import (
	"github.com/just-an-oldsalt/proto-mcp/internal/keystore"
	"github.com/just-an-oldsalt/proto-mcp/internal/secret"
)

// loadStoreKey returns the mirror key from the macOS Keychain, creating
// it on first use. The directory is unused: the key is not stored next
// to the database.
func loadStoreKey(dir string) (secret.Secret, error) {
	_ = dir
	return keystore.LoadOrCreateStoreKey()
}
