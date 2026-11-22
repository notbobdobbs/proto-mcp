package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSealRoundTripAndTamper(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain")
	sealed := filepath.Join(dir, "sealed")
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	// Three chunks plus a short tail, so the last chunk is partial.
	body := bytes.Repeat([]byte("marker-"), 20000)
	body = append(body, []byte("tail")...)
	if err := os.WriteFile(plain, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := sealFileAtomic(sealed, plain, key[:]); err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, err := os.ReadFile(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(got, []byte("marker-")) {
		t.Fatal("sealed file contains plaintext")
	}
	if !bytes.HasPrefix(got, []byte(sealMagic)) {
		t.Fatalf("sealed prefix = %q", got[:min(8, len(got))])
	}

	out := filepath.Join(dir, "out")
	if err := unsealFile(out, sealed, key[:]); err != nil {
		t.Fatalf("unseal: %v", err)
	}
	round, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(round, body) {
		t.Fatalf("round trip len %d, want %d", len(round), len(body))
	}

	var other [32]byte
	other[0] = 1
	if err := unsealFile(filepath.Join(dir, "bad"), sealed, other[:]); err == nil {
		t.Fatal("wrong key unsealed the file")
	}
	got[len(got)-1] ^= 0xff
	if err := os.WriteFile(sealed, got, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unsealFile(filepath.Join(dir, "tampered"), sealed, key[:]); err == nil {
		t.Fatal("tampered file unsealed")
	}
	// The original plaintext destination from the failed unseal must not
	// have been replaced with a partial.
	if _, err := os.Stat(filepath.Join(dir, "tampered")); !os.IsNotExist(err) {
		t.Fatal("failed unseal left an output file")
	}
}

func TestFileStoreSealsBodies(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "store.db")
	secretBody := "body-marker-" + strings.Repeat("s3cret", 4000)
	secretSubject := "subject-marker-unique"

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ctx := context.Background()
	m := Message{
		ID: "msg-seal", ThreadID: "thr", Subject: secretSubject,
		FromAddress: "alice@example.com", FromName: "Alice",
		ToJSON: `[{"address":"bob@example.com"}]`,
		Date:   time.Unix(1_700_000_000, 0).UTC(),
		Unread: true, Folder: "inbox", SizeBytes: int64(len(secretBody)),
		RawJSON: `{"ID":"msg-seal"}`,
	}
	if err := s.UpsertMessage(ctx, m); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := s.SetCachedBody(ctx, m.ID, CachedBody{Text: secretBody}); err != nil {
		t.Fatalf("set body: %v", err)
	}
	if err := sealOpenDB(s.DB, s.live, s.Path, s.key.Bytes()); err != nil {
		t.Fatalf("seal while open: %v", err)
	}
	sealed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.HasPrefix(sealed, []byte("SQLite format 3")) || bytes.Contains(sealed, []byte(secretBody)) || bytes.Contains(sealed, []byte(secretSubject)) {
		t.Fatal("canonical mirror is readable plaintext while the store is open")
	}
	if !bytes.HasPrefix(sealed, []byte(sealMagic)) {
		t.Fatal("canonical mirror is not sealed")
	}
	// Darwin keeps the mirror key in the Keychain, not store.key.
	// Non-darwin tests (and only those) create that file.
	if runtime.GOOS != "darwin" {
		info, err := os.Stat(filepath.Join(dir, "store.key"))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("store.key mode = %#o, want 0600", info.Mode().Perm())
		}
	}

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(path + ".live"); !os.IsNotExist(err) {
		t.Fatalf("working file remains after last close: %v", err)
	}

	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got, err := s2.GetMessage(ctx, m.ID)
	if err != nil {
		t.Fatalf("GetMessage: %v", err)
	}
	if got.Subject != secretSubject {
		t.Fatalf("subject = %q", got.Subject)
	}
	body, err := s2.GetCachedBody(ctx, m.ID)
	if err != nil {
		t.Fatalf("GetCachedBody: %v", err)
	}
	if body.Text != secretBody {
		t.Fatal("reopened body does not match")
	}
	if err := s2.Close(); err != nil {
		t.Fatal(err)
	}

	// A different key must fail closed and leave the sealed file in place.
	if os.Getenv("PROTONMCP_STORE_KEY") != "" {
		t.Setenv("PROTONMCP_STORE_KEY", strings.Repeat("77", 32))
	} else if runtime.GOOS != "darwin" {
		if err := os.WriteFile(filepath.Join(dir, "store.key"), bytes.Repeat([]byte{7}, 32), 0o600); err != nil {
			t.Fatal(err)
		}
	} else {
		t.Skip("swapping the macOS Keychain key is not part of this test")
	}
	if _, err := Open(path); err == nil {
		t.Fatal("Open with the wrong key succeeded")
	}
	still, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(still, []byte(sealMagic)) {
		t.Fatal("wrong-key open destroyed the sealed mirror")
	}
}

func TestPlaintextStoreIsMigratedAndShredded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "store.db")
	const marker = "legacy-plaintext-marker-bb19"

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE legacy_marker (v TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO legacy_marker (v) VALUES (?)`, marker); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open legacy: %v", err)
	}
	var got string
	if err := s.DB.QueryRow(`SELECT v FROM legacy_marker`).Scan(&got); err != nil {
		t.Fatalf("legacy row: %v", err)
	}
	if got != marker {
		t.Fatalf("legacy row = %q", got)
	}
	sealed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte(marker)) || bytes.HasPrefix(sealed, []byte("SQLite format 3")) {
		t.Fatal("legacy plaintext file was not replaced with ciphertext")
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Stat(path + suffix); !os.IsNotExist(err) {
			t.Errorf("plaintext sidecar %s still present", suffix)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if err := s2.DB.QueryRow(`SELECT v FROM legacy_marker`).Scan(&got); err != nil {
		t.Fatalf("legacy row after reopen: %v", err)
	}
	if got != marker {
		t.Fatalf("legacy row after reopen = %q", got)
	}
}

func TestSecondOpenerKeepsWorkingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "store.db")
	a, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".live"); err != nil {
		t.Fatalf("working file removed while another opener is live: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".live"); !os.IsNotExist(err) {
		t.Fatalf("working file remains after the last close: %v", err)
	}
}
