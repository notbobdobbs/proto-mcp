//go:build darwin

package keystore

import (
	"errors"
	"fmt"

	keychain "github.com/keybase/go-keychain"

	"github.com/just-an-oldsalt/proto-mcp/internal/secret"
)

// LoadHTTPToken reads the remote token. The item is
// AccessibleWhenUnlocked and not iCloud-synced, same as the mirror key.
func LoadHTTPToken() (secret.Secret, error) {
	data, err := keychain.GetGenericPassword(Service, HTTPTokenAccount, "", "")
	if err != nil {
		return secret.Secret{}, fmt.Errorf("keystore: read http token: %w", err)
	}
	if len(data) == 0 {
		return secret.Secret{}, ErrHTTPTokenNotFound
	}
	if len(data) != HTTPTokenLen {
		zero(data)
		return secret.Secret{}, errors.New("keystore: http token has the wrong length")
	}
	s := secret.New(data)
	zero(data)
	return s, nil
}

func init() {
	deleteHTTPTokenItem = func(service, account string) error {
		err := keychain.DeleteGenericPasswordItem(service, account)
		if err == nil || errors.Is(err, keychain.ErrorItemNotFound) {
			return nil
		}
		return err
	}
	addHTTPTokenItem = func(service, account, label string, data []byte) error {
		item := keychain.NewGenericPassword(service, account, label, data, "")
		item.SetSynchronizable(keychain.SynchronizableNo)
		item.SetAccessible(keychain.AccessibleWhenUnlocked)
		return keychain.AddItem(item)
	}
}

// DeleteHTTPToken removes the remote token. Missing is success.
func DeleteHTTPToken() error {
	err := keychain.DeleteGenericPasswordItem(Service, HTTPTokenAccount)
	if err == nil || errors.Is(err, keychain.ErrorItemNotFound) {
		return nil
	}
	return fmt.Errorf("keystore: delete http token: %w", err)
}
