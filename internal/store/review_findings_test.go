package store

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

// A zeroed or truncated header used to authenticate as an empty
// database and then replace the mirror. It must fail before any
// output file is created, and the existing mirror must stay.
func TestCorruptHeaderDoesNotReplaceMirror(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "mirror")
	const keep = "audit-log-and-messages-must-survive"
	if err := os.WriteFile(dst, []byte(keep), 0o600); err != nil {
		t.Fatal(err)
	}
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}

	cases := map[string][]byte{
		"empty":  {},
		"short":  []byte(sealMagic),
		"zeroed": append([]byte(sealMagic), make([]byte, sealHeaderLen)...),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			src := filepath.Join(dir, "bad-"+name)
			if err := os.WriteFile(src, body, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := unsealFile(dst, src, key[:]); err == nil {
				t.Fatal("corrupt header unsealed")
			}
			got, err := os.ReadFile(dst)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != keep {
				t.Fatalf("mirror changed to %q", got)
			}
			if _, err := os.Stat(src); err != nil {
				t.Fatalf("source sealed file was removed: %v", err)
			}
		})
	}
}

// Two seals of the same length share a key. A chunk taken from one
// and written into the other must not verify: the snapshot id is in
// the chunk's associated data.
func TestSplicedChunkFromOtherSnapshotFails(t *testing.T) {
	dir := t.TempDir()
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	plainA := bytes.Repeat([]byte("A"), sealChunkSize+10)
	plainB := bytes.Repeat([]byte("B"), sealChunkSize+10)
	write := func(name string, plain []byte) string {
		t.Helper()
		raw := filepath.Join(dir, name+".plain")
		out := filepath.Join(dir, name+".seal")
		if err := os.WriteFile(raw, plain, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := sealFileAtomic(out, raw, key[:]); err != nil {
			t.Fatal(err)
		}
		return out
	}
	a := write("a", plainA)
	b := write("b", plainB)
	ab, err := os.ReadFile(a)
	if err != nil {
		t.Fatal(err)
	}
	bb, err := os.ReadFile(b)
	if err != nil {
		t.Fatal(err)
	}
	// Replace B's first chunk (nonce, tag, ciphertext) with A's.
	n := sealHeaderLen + sealNonceLen + sealTagLen + sealChunkSize
	if len(ab) < n || len(bb) < n {
		t.Fatalf("sealed files shorter than one chunk: %d %d", len(ab), len(bb))
	}
	copy(bb[sealHeaderLen:n], ab[sealHeaderLen:n])
	spliced := filepath.Join(dir, "spliced")
	if err := os.WriteFile(spliced, bb, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unsealFile(filepath.Join(dir, "out"), spliced, key[:]); err == nil {
		t.Fatal("spliced chunk unsealed")
	}
}

func TestCheckpointBusyDoesNotDropWAL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "live.db")
	db, err := openSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE t (v TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO t (v) VALUES ('keep-me')`); err != nil {
		t.Fatal(err)
	}

	reader, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	tx, err := reader.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT v FROM t`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	err = checkpointTruncate(db)
	if err == nil {
		t.Fatal("busy checkpoint was treated as success")
	}
	if _, statErr := os.Stat(path + "-wal"); statErr != nil {
		t.Fatalf("WAL was removed after a busy checkpoint: %v", statErr)
	}
	var got string
	if err := db.QueryRow(`SELECT v FROM t`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != "keep-me" {
		t.Fatalf("row = %q", got)
	}
}

func TestMigrationStopsWhenCheckpointIsBusy(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "legacy.db")
	dst := filepath.Join(dir, "copy.db")
	db, err := openSQLite(src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE legacy_marker (v TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO legacy_marker (v) VALUES ('legacy-row')`); err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	reader, err := sql.Open("sqlite", src+"?_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	tx, err := reader.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT v FROM legacy_marker`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	// A write after the reader starts leaves frames the checkpoint
	// cannot move while that read is open.
	if _, err := db.Exec(`INSERT INTO legacy_marker (v) VALUES ('second')`); err != nil {
		t.Fatal(err)
	}

	if err := checkpointAndCopy(src, dst); err == nil {
		t.Fatal("migration copied a database whose checkpoint was busy")
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatalf("partial migration copy exists: %v", err)
	}
	if _, err := os.Stat(src + "-wal"); err != nil {
		t.Fatalf("source WAL missing: %v", err)
	}
}

func TestSealTempDoesNotFollowSymlink(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "sealed")
	// The previous temp name. Opening it with O_TRUNC would have
	// overwritten victim.
	if err := os.Symlink(victim, dst+".tmp"); err != nil {
		t.Fatal(err)
	}
	plain := filepath.Join(dir, "plain")
	if err := os.WriteFile(plain, []byte("payload-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	if err := sealFileAtomic(dst, plain, key[:]); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "original" {
		t.Fatalf("symlink target was overwritten: %q", got)
	}
	if _, err := os.Lstat(dst + ".tmp"); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentSealDoesNotCorrupt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "store.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.DB.Exec(`CREATE TABLE IF NOT EXISTS t (v TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`INSERT INTO t (v) VALUES ('concurrent')`); err != nil {
		t.Fatal(err)
	}
	errCh := make(chan error, 4)
	for range 4 {
		go func() {
			errCh <- sealOpenDB(s.DB, s.live, s.Path, s.key.Bytes())
		}()
	}
	for range 4 {
		if err := <-errCh; err != nil {
			t.Error(err)
		}
	}
	out := filepath.Join(dir, "check")
	if err := unsealFile(out, path, s.key.Bytes()); err != nil {
		t.Fatalf("sealed file after concurrent snapshots: %v", err)
	}
	if !isSQLiteFile(out) {
		t.Fatal("concurrent seal did not produce a database")
	}
}

func TestOpenMarksWALForNoDump(t *testing.T) {
	var got []string
	prev := markNoDump
	markNoDump = func(p string) { got = append(got, p) }
	t.Cleanup(func() { markNoDump = prev })

	dir := t.TempDir()
	path := filepath.Join(dir, "live.db")
	db, err := openSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	wantMain, wantWAL := false, false
	for _, p := range got {
		if p == path {
			wantMain = true
		}
		if p == path+"-wal" {
			wantWAL = true
		}
	}
	if !wantMain || !wantWAL {
		t.Fatalf("no-dump paths = %v, want the database and its WAL", got)
	}
}
