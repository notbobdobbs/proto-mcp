//go:build !darwin

package keystore

import "errors"

// Save, Load, Exists, and Delete need the macOS Keychain. These
// stubs exist so the package compiles on Linux, where the tests
// run. They do not store a session. The refusal checks in
// validate still run before Save reports that.
func Save(l Live) error {
	if err := l.validate(); err != nil {
		return err
	}
	return errors.New("keystore: session storage requires the macOS Keychain")
}

func Load() (Live, error) {
	return Live{}, errors.New("keystore: session storage requires the macOS Keychain")
}

func Exists() (bool, error) {
	return false, errors.New("keystore: session storage requires the macOS Keychain")
}

func Delete() error {
	return errors.New("keystore: session storage requires the macOS Keychain")
}
