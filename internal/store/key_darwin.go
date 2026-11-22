//go:build darwin

package store

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/just-an-oldsalt/proto-mcp/internal/keystore"
	"github.com/just-an-oldsalt/proto-mcp/internal/secret"
)

// loadStoreKey returns the mirror key from the macOS Keychain, creating
// it on first use. The directory is unused: the key is not stored next
// to the database.
//
// PROTONMCP_STORE_KEY (64 hex chars) is honored only by a test binary.
// GitHub's macOS runner blocks in SecItemAdd waiting for a keychain
// dialog; the race job sets this so store tests do not touch that
// keychain. A production binary refuses the variable.
func loadStoreKey(dir string) (secret.Secret, error) {
	_ = dir
	if s, ok, err := testStoreKey(); ok || err != nil {
		return s, err
	}
	return keystore.LoadOrCreateStoreKey()
}

func testStoreKey() (secret.Secret, bool, error) {
	raw := os.Getenv("PROTONMCP_STORE_KEY")
	if raw == "" {
		return secret.Secret{}, false, nil
	}
	if !strings.HasSuffix(filepath.Base(os.Args[0]), ".test") {
		return secret.Secret{}, false, errors.New("store: PROTONMCP_STORE_KEY is only honored by test binaries")
	}
	b, err := hex.DecodeString(raw)
	if err != nil || len(b) != 32 {
		return secret.Secret{}, true, errors.New("store: PROTONMCP_STORE_KEY must be 64 hex characters")
	}
	return secret.New(b), true, nil
}
