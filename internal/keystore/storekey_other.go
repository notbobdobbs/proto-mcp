//go:build !darwin

package keystore

import (
	"errors"

	"github.com/just-an-oldsalt/proto-mcp/internal/secret"
)

// LoadOrCreateStoreKey is the macOS Keychain entry point. Non-darwin
// builds have no Keychain; the store package uses a file key for tests.
func LoadOrCreateStoreKey() (secret.Secret, error) {
	return secret.Secret{}, errors.New("keystore: store key requires the macOS Keychain")
}
