//go:build darwin

package keystore

import (
	"encoding/json"
	"errors"
	"fmt"

	keychain "github.com/keybase/go-keychain"

	"github.com/just-an-oldsalt/proto-mcp/internal/secret"
)

// Save writes (or overwrites) the single session slot.
//
// Uses the keybase/go-keychain path with AccessibleWhenUnlocked. The
// Phase-7/D SecAccessControl path is intentionally NOT called here
// — see the blobVersion comment for why (restricted-entitlement wall).
func Save(l Live) error {
	if err := l.validate(); err != nil {
		return err
	}
	blob := savedBlob{
		Email:         l.Email,
		UID:           l.UID,
		AccessToken:   l.AccessToken,
		RefreshToken:  l.RefreshToken,
		SaltedKeyPass: l.SaltedKeyPass.Bytes(),
		Cookies:       l.Cookies,
		Version:       blobVersion,
	}
	data, err := json.Marshal(blob)
	if err != nil {
		return fmt.Errorf("marshal blob: %w", err)
	}
	defer zero(data)

	item := keychain.NewGenericPassword(Service, Account, Label, data, "")
	item.SetSynchronizable(keychain.SynchronizableNo)
	item.SetAccessible(keychain.AccessibleWhenUnlocked)

	err = keychain.AddItem(item)
	if errors.Is(err, keychain.ErrorDuplicateItem) {
		query := keychain.NewItem()
		query.SetSecClass(keychain.SecClassGenericPassword)
		query.SetService(Service)
		query.SetAccount(Account)

		update := keychain.NewItem()
		update.SetData(data)
		update.SetLabel(Label)
		return keychain.UpdateItem(query, update)
	}
	return err
}

// Load reads the stored session. Returns ErrNotFound if absent.
func Load() (Live, error) {
	data, err := keychain.GetGenericPassword(Service, Account, "", "")
	if err != nil {
		return Live{}, fmt.Errorf("keychain get: %w", err)
	}
	if data == nil {
		return Live{}, ErrNotFound
	}
	defer zero(data)

	var blob savedBlob
	if err := json.Unmarshal(data, &blob); err != nil {
		return Live{}, fmt.Errorf("decode blob: %w", err)
	}

	// Version migrations. v3 is current; older versions read with a
	// compat decoder + are silently rewritten as v3 on the next Save
	// (the caller of Load is typically about to call Resume → which
	// triggers a token rotation → which fires OnAuthUpdate → which
	// re-Saves). No user action required.
	switch blob.Version {
	case blobVersion:
		// happy path
	case 4:
		// Briefly-shipped v4 (Phase 7/D SecAccessControl). Same JSON
		// shape, just a different version marker. Treat as v3 — the
		// next Save will write a v3-flagged blob. No data lost.
	case 2:
		// v2 stored the salted key pass as a base64 STRING under the
		// "salted_key_pass_b64" field. Decode it here, populate the
		// v3-shaped slice in `blob` so the rest of Load doesn't care.
		raw, err := loadV2Salt(data)
		if err != nil {
			return Live{}, fmt.Errorf("migrate v2 blob: %w", err)
		}
		blob.SaltedKeyPass = raw
	default:
		return Live{}, fmt.Errorf("keystore: unknown blob version %d (expected %d) — run `protonmcp logout && protonmcp login`",
			blob.Version, blobVersion)
	}

	live := Live{
		Email:         blob.Email,
		UID:           blob.UID,
		AccessToken:   blob.AccessToken,
		RefreshToken:  blob.RefreshToken,
		SaltedKeyPass: secret.New(blob.SaltedKeyPass),
		Cookies:       blob.Cookies,
	}
	// Zero the unmarshaled bytes so the only copy of the salted key
	// material now lives inside the Secret. The data buffer at the
	// top of this function will also be zeroed by its defer.
	zero(blob.SaltedKeyPass)
	return live, nil
}

// Exists reports whether a session blob is stored, WITHOUT reading
// the secret payload. Attributes-only Keychain query — no copy of
// the token/key material is materialized in this process.
//
// D43: protonmcpd calls this before the Touch ID startup gate so a
// missing session fails fast with "run `protonmcp login`" instead of
// prompting the user to unlock a blob that doesn't exist.
func Exists() (bool, error) {
	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassGenericPassword)
	query.SetService(Service)
	query.SetAccount(Account)
	query.SetMatchLimit(keychain.MatchLimitOne)
	query.SetReturnAttributes(true)
	// QueryItem maps errSecItemNotFound to (nil, nil), so a nil error
	// with zero results is the canonical "no entry" signal.
	results, err := keychain.QueryItem(query)
	if err != nil {
		return false, fmt.Errorf("keychain query: %w", err)
	}
	return len(results) > 0, nil
}

// Delete removes the stored session. Returns nil if no entry exists
// (idempotent — useful for logout flows that don't want to fail when
// the user was never logged in).
func Delete() error {
	err := keychain.DeleteGenericPasswordItem(Service, Account)
	if errors.Is(err, keychain.ErrorItemNotFound) {
		return nil
	}
	return err
}
