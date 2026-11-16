//go:build !darwin

package keystore

import (
	"errors"

	"github.com/just-an-oldsalt/proto-mcp/internal/secret"
)

// LoadHTTPToken, SaveHTTPToken, and DeleteHTTPToken need the macOS
// Keychain. These stubs do not store a token.
func LoadHTTPToken() (secret.Secret, error) {
	return secret.Secret{}, errors.New("keystore: http token requires the macOS Keychain")
}

func SaveHTTPToken(secret.Secret) error {
	return errors.New("keystore: http token requires the macOS Keychain")
}

func DeleteHTTPToken() error {
	return errors.New("keystore: http token requires the macOS Keychain")
}
