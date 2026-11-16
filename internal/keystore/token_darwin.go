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

// SaveHTTPToken writes or replaces the remote token. data must be 32 bytes.
func SaveHTTPToken(s secret.Secret) error {
	if len(s.Bytes()) != HTTPTokenLen {
		return errors.New("keystore: http token has the wrong length")
	}
	data := make([]byte, HTTPTokenLen)
	copy(data, s.Bytes())
	defer zero(data)

	item := keychain.NewGenericPassword(Service, HTTPTokenAccount, HTTPTokenLabel, data, "")
	item.SetSynchronizable(keychain.SynchronizableNo)
	item.SetAccessible(keychain.AccessibleWhenUnlocked)
	err := keychain.AddItem(item)
	if errors.Is(err, keychain.ErrorDuplicateItem) {
		query := keychain.NewItem()
		query.SetSecClass(keychain.SecClassGenericPassword)
		query.SetService(Service)
		query.SetAccount(HTTPTokenAccount)
		update := keychain.NewItem()
		update.SetData(data)
		update.SetLabel(HTTPTokenLabel)
		if err := keychain.UpdateItem(query, update); err != nil {
			return fmt.Errorf("keystore: replace http token: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("keystore: save http token: %w", err)
	}
	return nil
}

// DeleteHTTPToken removes the remote token. Missing is success.
func DeleteHTTPToken() error {
	err := keychain.DeleteGenericPasswordItem(Service, HTTPTokenAccount)
	if err == nil || errors.Is(err, keychain.ErrorItemNotFound) {
		return nil
	}
	return fmt.Errorf("keystore: delete http token: %w", err)
}
