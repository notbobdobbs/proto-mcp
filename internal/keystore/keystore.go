// Package keystore persists Proton session state to the macOS Keychain
// so a fresh process can resume work without re-running the full SRP +
// 2FA + keyring-unlock flow.
//
// One Keychain item per machine, identified by Service + Account below.
// The item's secret payload is a JSON blob containing the email, the
// session UID, the rotating access / refresh tokens, and the SRP-derived
// salted mailbox-password (base64'd). The Keychain handles encryption
// at rest; this package just brokers the in/out conversion.
//
// Multi-account support is deliberately out of scope for now — there's
// one slot, and `protonmcp login` overwrites whatever was there.
package keystore

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/just-an-oldsalt/proto-mcp/internal/secret"
)

const (
	// Service is the macOS Keychain service identifier under which the
	// session blob is filed. Matches the launchd label placeholder used
	// throughout the design spec; will become a real bundle identifier
	// once the daemon is signed.
	Service = "zone.dort.protonmcp"

	// Account is the single per-machine slot the v1 keystore uses.
	// Multi-account would put the email here instead.
	Account = "session"

	// Label is what shows up in Keychain Access.app for humans.
	Label = "Proton MCP session"
)

// ErrNotFound is returned by Load and Delete when no session is stored.
var ErrNotFound = errors.New("keystore: no stored session")

// errKeychainItemNotFound is the platform "no such item" signal.
// Delete treats it as success so logout is idempotent.
var errKeychainItemNotFound = errors.New("keystore: item not found")

// deleteKeychainItem removes one item under Service. The macOS
// build replaces this with the real Keychain call. Logout passes
// only the session account, so the mirror key and the remote token
// stay. Tests replace it with a fake.
var deleteKeychainItem = func(service, account string) error {
	return errors.New("keystore: session storage requires the macOS Keychain")
}

// Delete removes the stored session. Returns nil if no entry exists.
// It deletes only the session account. The mailbox-mirror key and
// the remote HTTP token are separate Keychain items and are left
// in place.
func Delete() error {
	err := deleteKeychainItem(Service, Account)
	if err == nil || errors.Is(err, errKeychainItemNotFound) {
		return nil
	}
	return err
}

// Live is the in-memory shape of a stored session. SaltedKeyPass is a
// secret.Secret because it's the binary used to re-unlock the user's
// PGP keyring — just as sensitive as the mailbox password.
//
// Cookies carries the http.Cookie values set by /auth/v4 during the
// initial SRP login. Proton's refresh endpoint is cookie-bound: a
// cold-process resume with the right UID + refresh token still hits
// 422 "Invalid refresh token" unless the same session cookies are
// sent. We persist them alongside the tokens so a fresh process can
// rebuild the jar exactly as the SDK left it.
type Live struct {
	Email         string
	UID           string
	AccessToken   string
	RefreshToken  string
	SaltedKeyPass secret.Secret
	Cookies       []*http.Cookie
}

// Zero wipes secret material on the Live value.
func (l *Live) Zero() {
	l.SaltedKeyPass.Zero()
	// Tokens are still string-valued — Go strings can't be zeroed, so
	// the best we can do is drop the reference and let GC reclaim.
	l.AccessToken = ""
	l.RefreshToken = ""
}

// savedBlob is the on-disk shape (in the Keychain blob). Kept private
// so callers can't accidentally hand a json.Marshal-able struct around
// the codebase.
//
// SaltedKeyPass is []byte rather than a base64'd string deliberately
// (SECURITY B-1): encoding/json natively marshals []byte → base64 on
// write and base64 → []byte on read, so the raw key material goes
// through json.Marshal as a slice we can zero (defer zero(data) below),
// not as a Go string that lives in the GC heap until reclaimed.
type savedBlob struct {
	Email         string         `json:"email"`
	UID           string         `json:"uid"`
	AccessToken   string         `json:"access_token"`
	RefreshToken  string         `json:"refresh_token"`
	SaltedKeyPass []byte         `json:"salted_key_pass"`
	Cookies       []*http.Cookie `json:"cookies,omitempty"`
	Version       int            `json:"v"`
}

// blobVersion gets bumped when the JSON shape changes incompatibly.
// Old blobs from a previous version are rejected (forcing the user to
// re-login) rather than silently misinterpreted.
//
// History:
//
//	v1: original {email, uid, access_token, refresh_token, salted_key_pass_b64}
//	v2: added cookies (required for cold-start refresh — see Live doc)
//	v3: SaltedKeyPass migrated from base64 string to []byte (SECURITY B-1)
//
// v4 was briefly introduced for Phase 7/D's SecAccessControl-based
// keychain ACL hardening but rolled back: the cgo path required a
// `keychain-access-groups` entitlement, which is a "restricted
// entitlement" on macOS — Developer ID Application signing alone is
// not authorized for it; you need an Apple-provisioned profile
// embedded in the binary (Phase 7/E .app-bundle work). Without the
// profile, the kernel SIGKILLs the binary at launch. D37 is reopened
// and deferred to Phase 7/E. The cgo wrapper in
// access_control_darwin.{h,c,go} stays in tree, dormant, ready to
// re-enable once the bundle work lands.
const blobVersion = 3

// v2 used a base64-encoded string for the salted key pass. The bytes
// it encodes are identical to what v3 ships as a []byte (Go's json
// happens to encode []byte to base64 too), so the migration is just
// "decode the string, install it in the new field."
func loadV2Salt(data []byte) ([]byte, error) {
	var legacy struct {
		B64 string `json:"salted_key_pass_b64"`
	}
	if err := json.Unmarshal(data, &legacy); err != nil {
		return nil, fmt.Errorf("decode legacy field: %w", err)
	}
	if legacy.B64 == "" {
		return nil, errors.New("v2 blob missing salted_key_pass_b64 field")
	}
	raw, err := base64.StdEncoding.DecodeString(legacy.B64)
	if err != nil {
		return nil, fmt.Errorf("decode legacy base64: %w", err)
	}
	return raw, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// allZero reports whether every byte of b is zero.
func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// validate holds Save's refusal checks. Kept separate from the
// Keychain write so tests can exercise the guards without any path to
// the real Keychain item (there is one per machine — see Service).
func (l Live) validate() error {
	if l.Email == "" || l.UID == "" || l.RefreshToken == "" {
		return errors.New("keystore: refusing to save incomplete session (need email, uid, refresh_token)")
	}
	// SECURITY D16 / B-14: refuse to write a blob whose
	// SaltedKeyPass got zeroed mid-flight. Without this guard, a
	// Close-vs-OnAuthUpdate race silently corrupts the Keychain
	// entry — next Resume fails at the key-unlock step with no
	// diagnostic clue. Pair with C-4 (OnAuthUpdate guard).
	if len(l.SaltedKeyPass.Bytes()) == 0 {
		return errors.New("keystore: refusing to save empty SaltedKeyPass (D16: likely Close/OnAuthUpdate race)")
	}
	// Issue #123: a zeroed-but-not-detached pass (a value copy of a
	// Secret whose sharer called Zero) keeps its length, so the check
	// above misses it. A real salted pass is never all zero bytes.
	if allZero(l.SaltedKeyPass.Bytes()) {
		return errors.New("keystore: refusing to save all-zero SaltedKeyPass (#123: zeroed shared backing array)")
	}
	return nil
}
