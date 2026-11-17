package keystore

import (
	"runtime"
	"strings"
	"testing"

	"github.com/just-an-oldsalt/proto-mcp/internal/secret"
)

// Issue #123: a zeroed-but-not-detached pass keeps its length, so the
// empty check alone let an all-zero pass reach the Keychain. Save must
// refuse it. Tests call validate(), never Save(): Save writes the one
// real per-machine Keychain item, so a regression in a guard would
// otherwise clobber the developer's stored session.
func TestValidateRefusesAllZeroSaltedKeyPass(t *testing.T) {
	err := Live{
		Email:         "a@b.c",
		UID:           "uid",
		RefreshToken:  "refresh",
		SaltedKeyPass: secret.New(make([]byte, 32)),
	}.validate()
	if err == nil || !strings.Contains(err.Error(), "all-zero") {
		t.Fatalf("validate with an all-zero pass = %v, want an all-zero refusal", err)
	}
}

// Non-macOS builds have no Keychain. Save must still refuse an
// all-zero pass, and a well-formed session must not be reported as
// stored.
func TestSaveWithoutKeychainRefusesAndDoesNotSucceed(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("macOS Save writes the real Keychain item")
	}
	err := Save(Live{
		Email:         "synthetic@example.com",
		UID:           "uid",
		RefreshToken:  "refresh",
		SaltedKeyPass: secret.New(make([]byte, 32)),
	})
	if err == nil || !strings.Contains(err.Error(), "all-zero") {
		t.Fatalf("Save(all-zero) = %v, want the all-zero refusal", err)
	}
	pass := make([]byte, 32)
	pass[0] = 1
	err = Save(Live{
		Email:         "synthetic@example.com",
		UID:           "uid",
		RefreshToken:  "refresh",
		SaltedKeyPass: secret.New(pass),
	})
	if err == nil || !strings.Contains(err.Error(), "macOS Keychain") {
		t.Fatalf("Save = %v, want a Keychain-required error", err)
	}
}
