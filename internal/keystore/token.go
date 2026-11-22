package keystore

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/just-an-oldsalt/proto-mcp/internal/secret"
)

const (
	// StoreKeyAccount is the Keychain account for the mailbox-mirror
	// data key. It sits next to the session item (Account) under the
	// same service, and it is not the session secret: losing it makes
	// the local mirror unreadable, not the Proton account. Logout
	// does not delete it.
	StoreKeyAccount = "store-key"

	// StoreKeyLabel is what Keychain Access shows for the item.
	StoreKeyLabel = "Proton MCP mailbox mirror"

	// HTTPTokenAccount is the Keychain account for the remote-door
	// bearer token. It sits next to the session and the mirror key
	// under the same service. Logout does not delete it.
	HTTPTokenAccount = "http-bearer"

	// HTTPTokenLabel is what Keychain Access shows for the item.
	HTTPTokenLabel = "Proton MCP remote token"

	// HTTPTokenLen is the raw token size. 32 bytes from crypto/rand.
	HTTPTokenLen = 32
)

// ErrHTTPTokenNotFound means no remote token is stored.
var ErrHTTPTokenNotFound = errors.New("keystore: no remote token")

// constantTimeCompare is subtle.ConstantTimeCompare. Tests replace it
// to prove equal-length tokens are compared that way, and that a
// different length never reaches it. Not a timing measurement.
var constantTimeCompare = subtle.ConstantTimeCompare

// deleteHTTPTokenItem and addHTTPTokenItem are the Keychain calls
// behind SaveHTTPToken. The macOS build replaces them. Save deletes
// the old item and adds a new one so AccessibleWhenUnlocked and
// not-synced are set on the new item, not left over from an update.
var (
	deleteHTTPTokenItem = func(service, account string) error {
		return errors.New("keystore: http token requires the macOS Keychain")
	}
	addHTTPTokenItem = func(service, account, label string, data []byte) error {
		return errors.New("keystore: http token requires the macOS Keychain")
	}
)

// SaveHTTPToken writes or replaces the remote token. data must be 32
// bytes. Replacement deletes the old item and adds a new one.
func SaveHTTPToken(s secret.Secret) error {
	if len(s.Bytes()) != HTTPTokenLen {
		return errors.New("keystore: http token has the wrong length")
	}
	data := make([]byte, HTTPTokenLen)
	copy(data, s.Bytes())
	defer zero(data)
	if err := deleteHTTPTokenItem(Service, HTTPTokenAccount); err != nil {
		return fmt.Errorf("keystore: delete http token before replace: %w", err)
	}
	if err := addHTTPTokenItem(Service, HTTPTokenAccount, HTTPTokenLabel, data); err != nil {
		return fmt.Errorf("keystore: save http token: %w", err)
	}
	return nil
}

// GenerateHTTPToken returns 32 random bytes in a Secret. The caller
// zeros the Secret when finished.
func GenerateHTTPToken() (secret.Secret, error) {
	b := make([]byte, HTTPTokenLen)
	if _, err := rand.Read(b); err != nil {
		return secret.Secret{}, err
	}
	defer zero(b)
	return secret.New(b), nil
}

// HTTPTokenEqual reports whether stored and presented are the same
// 32-byte token. A different length is false and is not compared
// against the secret.
func HTTPTokenEqual(stored, presented []byte) bool {
	if len(stored) != HTTPTokenLen || len(presented) != HTTPTokenLen {
		return false
	}
	return constantTimeCompare(stored, presented) == 1
}

// EncodeHTTPToken is the text form copied to the clipboard and sent
// as the bearer token. It is hex, lowercase, 64 characters.
func EncodeHTTPToken(raw []byte) (string, error) {
	if len(raw) != HTTPTokenLen {
		return "", errors.New("keystore: http token has the wrong length")
	}
	return hex.EncodeToString(raw), nil
}

// HTTPTokenMatches decodes a presented bearer string and compares it
// with the stored token. Bad hex or the wrong length is false and
// does not compare against the secret.
func HTTPTokenMatches(stored []byte, presented string) bool {
	raw, err := hex.DecodeString(strings.TrimSpace(presented))
	if err != nil {
		return false
	}
	defer zero(raw)
	return HTTPTokenEqual(stored, raw)
}
