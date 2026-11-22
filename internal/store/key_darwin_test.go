//go:build darwin

package store

import (
	"strings"
	"testing"
)

func TestLoadStoreKeyHonorsTestEnv(t *testing.T) {
	t.Setenv("PROTONMCP_STORE_KEY", strings.Repeat("ab", 32))
	s, err := loadStoreKey(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Zero()
	if len(s.Bytes()) != 32 {
		t.Fatalf("len %d, want 32", len(s.Bytes()))
	}
}

func TestLoadStoreKeyRejectsShortTestEnv(t *testing.T) {
	t.Setenv("PROTONMCP_STORE_KEY", "abcd")
	if _, err := loadStoreKey(t.TempDir()); err == nil {
		t.Fatal("short PROTONMCP_STORE_KEY was accepted")
	}
}
