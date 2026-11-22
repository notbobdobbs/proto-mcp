//go:build darwin

package keystore

import (
	"crypto/rand"
	"errors"
	"fmt"

	keychain "github.com/keybase/go-keychain"

	"github.com/just-an-oldsalt/proto-mcp/internal/secret"
)

// LoadOrCreateStoreKey returns the 32-byte AES key that seals the
// local mailbox mirror, creating it the first time. The item is
// AccessibleWhenUnlocked and not iCloud-synced, same as the session
// blob — a backup of Application Support without this Keychain item
// cannot decrypt the mirror.
func LoadOrCreateStoreKey() (secret.Secret, error) {
	data, err := keychain.GetGenericPassword(Service, StoreKeyAccount, "", "")
	if err != nil {
		return secret.Secret{}, fmt.Errorf("keystore: read store key: %w", err)
	}
	if len(data) == 32 {
		s := secret.New(data)
		zero(data)
		return s, nil
	}
	if len(data) > 0 {
		zero(data)
		return secret.Secret{}, errors.New("keystore: store key has the wrong length; not overwriting it")
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return secret.Secret{}, fmt.Errorf("keystore: generate store key: %w", err)
	}
	defer zero(key)

	item := keychain.NewGenericPassword(Service, StoreKeyAccount, StoreKeyLabel, key, "")
	item.SetSynchronizable(keychain.SynchronizableNo)
	item.SetAccessible(keychain.AccessibleWhenUnlocked)
	if err := keychain.AddItem(item); err != nil {
		if errors.Is(err, keychain.ErrorDuplicateItem) {
			return LoadOrCreateStoreKey()
		}
		return secret.Secret{}, fmt.Errorf("keystore: save store key: %w", err)
	}
	return secret.New(key), nil
}
