package keystore

import (
	"bytes"
	"crypto/subtle"
	"runtime"
	"strings"
	"testing"
)

func TestDeleteRemovesOnlyTheSession(t *testing.T) {
	items := map[string]string{
		Account:          "session-blob",
		StoreKeyAccount:  "mirror-key",
		HTTPTokenAccount: "remote-token",
	}
	prev := deleteKeychainItem
	t.Cleanup(func() { deleteKeychainItem = prev })
	deleteKeychainItem = func(service, account string) error {
		if service != Service {
			t.Errorf("service = %q, want %q", service, Service)
		}
		delete(items, account)
		return nil
	}
	if err := Delete(); err != nil {
		t.Fatal(err)
	}
	if _, ok := items[Account]; ok {
		t.Fatal("logout left the session item")
	}
	if items[StoreKeyAccount] != "mirror-key" {
		t.Fatal("logout removed the mirror key")
	}
	if items[HTTPTokenAccount] != "remote-token" {
		t.Fatal("logout removed the remote token")
	}
}

func TestHTTPTokenEqualUsesConstantTimeForFullLengthOnly(t *testing.T) {
	var calls int
	prev := constantTimeCompare
	t.Cleanup(func() { constantTimeCompare = prev })
	constantTimeCompare = func(a, b []byte) int {
		calls++
		if len(a) != len(b) || len(a) != HTTPTokenLen {
			t.Errorf("compare saw lengths %d and %d", len(a), len(b))
		}
		return subtle.ConstantTimeCompare(a, b)
	}

	good := bytes.Repeat([]byte{7}, HTTPTokenLen)
	other := bytes.Repeat([]byte{8}, HTTPTokenLen)
	if !HTTPTokenEqual(good, append([]byte(nil), good...)) {
		t.Fatal("equal tokens did not match")
	}
	if HTTPTokenEqual(good, other) {
		t.Fatal("different tokens matched")
	}
	if calls != 2 {
		t.Fatalf("equal-length compares = %d, want 2", calls)
	}
	if HTTPTokenEqual(good, good[:16]) {
		t.Fatal("short token matched")
	}
	if HTTPTokenEqual(good, append(good, 1)) {
		t.Fatal("long token matched")
	}
	if HTTPTokenEqual(nil, nil) {
		t.Fatal("empty token matched")
	}
	if calls != 2 {
		t.Fatalf("a wrong length reached the compare, calls=%d", calls)
	}
}

func TestHTTPTokenMatchesRejectsBadTextWithoutComparing(t *testing.T) {
	raw := bytes.Repeat([]byte{9}, HTTPTokenLen)
	text, err := EncodeHTTPToken(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !HTTPTokenMatches(raw, text) {
		t.Fatal("hex of the token did not match")
	}
	if !HTTPTokenMatches(raw, strings.ToUpper(text)) {
		t.Fatal("uppercase hex did not match")
	}

	var calls int
	prev := constantTimeCompare
	t.Cleanup(func() { constantTimeCompare = prev })
	constantTimeCompare = func(a, b []byte) int {
		calls++
		return subtle.ConstantTimeCompare(a, b)
	}
	for _, presented := range []string{"", "zz", text[:10], text + "aa", "not-hex"} {
		if HTTPTokenMatches(raw, presented) {
			t.Fatalf("presented %q matched", presented)
		}
	}
	if calls != 0 {
		t.Fatalf("bad text reached the compare, calls=%d", calls)
	}
}

func TestGenerateHTTPTokenIs32Bytes(t *testing.T) {
	a, err := GenerateHTTPToken()
	if err != nil {
		t.Fatal(err)
	}
	defer a.Zero()
	b, err := GenerateHTTPToken()
	if err != nil {
		t.Fatal(err)
	}
	defer b.Zero()
	if len(a.Bytes()) != HTTPTokenLen || len(b.Bytes()) != HTTPTokenLen {
		t.Fatalf("lengths %d %d", len(a.Bytes()), len(b.Bytes()))
	}
	if bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatal("two generated tokens were identical")
	}
	if _, err := EncodeHTTPToken(a.Bytes()); err != nil {
		t.Fatal(err)
	}
	// The Secret string must not be the token.
	enc, _ := EncodeHTTPToken(a.Bytes())
	if strings.Contains(a.String(), enc) || strings.Contains(enc, "REDACTED") {
		t.Fatal("encoding or redaction looks wrong")
	}
}

func TestNonDarwinTokenStoreRefuses(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("macOS has a Keychain")
	}
	if _, err := LoadHTTPToken(); err == nil {
		t.Fatal("LoadHTTPToken succeeded without a Keychain")
	}
	tok, err := GenerateHTTPToken()
	if err != nil {
		t.Fatal(err)
	}
	defer tok.Zero()
	if err := SaveHTTPToken(tok); err == nil {
		t.Fatal("SaveHTTPToken succeeded without a Keychain")
	}
	if err := DeleteHTTPToken(); err == nil {
		t.Fatal("DeleteHTTPToken succeeded without a Keychain")
	}
}
