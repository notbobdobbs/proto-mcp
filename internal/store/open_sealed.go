package store

import (
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// openSealed opens the encrypted mirror at path. The database/sql
// handle uses a plaintext working file (path+".live") shared by every
// process that currently has the store open. The canonical path is
// ciphertext the whole time, including while the store is open.
//
// The first opener after a crash reuses a leftover working file (it
// has writes the sealed copy may not) and seals it again. The last
// Close seals and shreds the working file.
func openSealed(path string) (st *Store, err error) {
	if _, err := buildDSN(path); err != nil {
		return nil, err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}

	lock, err := lockExclusive(path + ".lock")
	if err != nil {
		return nil, err
	}
	defer unlockExclusive(lock)

	key, err := loadStoreKey(dir)
	if err != nil {
		return nil, err
	}
	owned := true
	defer func() {
		if owned {
			key.Zero()
		}
	}()

	pids, err := readLivePIDs(lock)
	if err != nil {
		return nil, err
	}
	live := path + ".live"
	if len(pids) == 0 {
		if err := materialize(path, live, key.Bytes()); err != nil {
			return nil, err
		}
	} else if !isSQLiteFile(live) {
		return nil, fmt.Errorf("store: %s is in use but the working file is missing", path)
	}

	db, err := openSQLite(live)
	if err != nil {
		return nil, err
	}
	defer func() {
		if db != nil {
			_ = db.Close()
		}
	}()

	// Seal before publishing our pid so a crash during the rest of
	// startup still leaves ciphertext at the canonical path. VACUUM
	// INTO, not a raw copy: the working file is in WAL mode and the
	// main file alone can be behind the log.
	if len(pids) == 0 {
		if err := sealOpenDBLocked(db, live, path, key.Bytes()); err != nil {
			return nil, err
		}
	}

	pids = append(pids, os.Getpid())
	if err := writePIDs(lock, pids); err != nil {
		return nil, err
	}

	s := &Store{DB: db, Path: path, live: live, key: key}
	db = nil
	owned = false
	s.startSealer()
	return s, nil
}

func (s *Store) startSealer() {
	s.sealStop = make(chan struct{})
	s.sealDone = make(chan struct{})
	go func() {
		defer close(s.sealDone)
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-s.sealStop:
				return
			case <-t.C:
				s.sealMu.Lock()
				_ = sealOpenDB(s.DB, s.live, s.Path, s.key.Bytes())
				s.sealMu.Unlock()
			}
		}
	}()
}

func (s *Store) close() error {
	if s.sealStop != nil {
		close(s.sealStop)
		<-s.sealDone
	}
	s.sealMu.Lock()
	defer s.sealMu.Unlock()

	var err error
	if s.DB != nil && s.live != "" {
		// The sealed copy is the main file, not the WAL. A busy
		// TRUNCATE checkpoint still returns no error from Exec; the
		// row's busy count is what says the log was not fully
		// copied. Shredding that log would drop committed pages.
		if cerr := checkpointTruncate(s.DB); cerr != nil {
			err = cerr
		}
	}
	if s.DB != nil {
		if cerr := s.DB.Close(); cerr != nil && err == nil {
			err = cerr
		}
		s.DB = nil
	}
	if s.live == "" {
		return err
	}
	defer s.key.Zero()
	if err != nil {
		// Leave the working files for the next open. Drop our pid so
		// that open is not stuck believing this process still has them.
		_ = s.dropPID()
		return err
	}
	return s.finishLive()
}

// dropPID removes this process from the opener list without sealing.
func (s *Store) dropPID() error {
	lock, err := lockExclusive(s.Path + ".lock")
	if err != nil {
		return err
	}
	defer unlockExclusive(lock)
	pids, err := readLivePIDs(lock)
	if err != nil {
		return err
	}
	return writePIDs(lock, removeOnePID(pids, os.Getpid()))
}

// finishLive drops this process from the opener list. The last opener
// seals the working file over the canonical path and shreds it.
func (s *Store) finishLive() error {
	lock, err := lockExclusive(s.Path + ".lock")
	if err != nil {
		return err
	}
	defer unlockExclusive(lock)

	pids, err := readLivePIDs(lock)
	if err != nil {
		return err
	}
	pids = removeOnePID(pids, os.Getpid())
	if len(pids) > 0 {
		return writePIDs(lock, pids)
	}
	if err := sealFileAtomic(s.Path, s.live, s.key.Bytes()); err != nil {
		_ = writePIDs(lock, nil)
		return err
	}
	var shredErr error
	for _, p := range []string{s.live, s.live + "-wal", s.live + "-shm", s.live + "-journal", s.live + ".snapshot"} {
		if err := shred(p); err != nil && shredErr == nil {
			shredErr = err
		}
	}
	if err := writePIDs(lock, nil); err != nil && shredErr == nil {
		shredErr = err
	}
	return shredErr
}

// checkpointTruncate runs a TRUNCATE checkpoint and requires it to
// finish. SQLite reports a blocked checkpoint as a successful query
// whose first column is non-zero (busy). That is a failure: the WAL
// still holds pages the main file does not.
func checkpointTruncate(db *sql.DB) error {
	var busy, logged, checkpointed int
	err := db.QueryRow("PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &logged, &checkpointed)
	if err != nil {
		return fmt.Errorf("store: checkpoint: %w", err)
	}
	if busy != 0 || logged != checkpointed {
		return fmt.Errorf("store: checkpoint incomplete (busy=%d, wal=%d, checkpointed=%d); keeping the WAL", busy, logged, checkpointed)
	}
	return nil
}

// sealOpenDB writes a consistent snapshot of an open database to dst.
// The caller must not already hold dst's lock in this process: taking
// it again and unlocking would drop that lock. openSealed calls
// sealOpenDBLocked while it holds the lock.
// destSealMu serializes seals of one mirror inside this process.
// flock is per-process, so two goroutines would not exclude each
// other with the file lock alone.
var (
	destSealMu  sync.Mutex
	destSealMus = map[string]*sync.Mutex{}
)

func mutexFor(dst string) *sync.Mutex {
	destSealMu.Lock()
	defer destSealMu.Unlock()
	m := destSealMus[dst]
	if m == nil {
		m = &sync.Mutex{}
		destSealMus[dst] = m
	}
	return m
}

func sealOpenDB(db *sql.DB, live, dst string, key []byte) error {
	if db == nil {
		return nil
	}
	mu := mutexFor(dst)
	mu.Lock()
	defer mu.Unlock()
	lock, err := lockExclusive(dst + ".lock")
	if err != nil {
		return err
	}
	defer unlockExclusive(lock)
	return sealOpenDBLocked(db, live, dst, key)
}

func sealOpenDBLocked(db *sql.DB, live, dst string, key []byte) error {
	if db == nil {
		return nil
	}
	// A private snapshot name per call. Two openers must not VACUUM
	// INTO one shared temp, and the file lock above keeps the rename
	// of the sealed mirror single-writer.
	var rnd [6]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	snap := fmt.Sprintf("%s.snapshot.%d.%x", live, os.Getpid(), rnd)
	if fi, err := os.Lstat(snap); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("store: refusing snapshot path %s (symlink)", snap)
		}
		return fmt.Errorf("store: snapshot path %s already exists", snap)
	}
	if _, err := db.Exec("VACUUM INTO " + sqlString(snap)); err != nil {
		return fmt.Errorf("store: snapshot working copy: %w", err)
	}
	defer shred(snap)
	hideWorkingFiles(snap)
	return sealFileAtomic(dst, snap, key)
}

func sqlString(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// materialize makes sure the working file exists and the canonical
// path is not leftover plaintext.
func materialize(path, live string, key []byte) error {
	_ = shred(live + ".snapshot")
	switch {
	case isSQLiteFile(live):
		// Crash leftover. It is newer than the sealed copy (writes
		// since the last seal). Keep it, and shred a plaintext
		// canonical file if an older build left one behind.
		if isSQLiteFile(path) {
			return shredSidecars(path)
		}
		return nil
	case isSQLiteFile(path):
		if err := checkpointAndCopy(path, live); err != nil {
			return err
		}
		// The copy is the working file. Shred the plaintext original
		// before sealOpenDB writes ciphertext back to path.
		return shredSidecars(path)
	case isSealedFile(path):
		return unsealFile(live, path, key)
	case !fileExists(path):
		return nil
	default:
		return fmt.Errorf("store: %s is neither a SQLite database nor an encrypted mirror", path)
	}
}

func shredSidecars(path string) error {
	for _, p := range []string{path, path + "-wal", path + "-shm", path + "-journal"} {
		if err := shred(p); err != nil {
			return err
		}
	}
	return nil
}

func checkpointAndCopy(src, dst string) error {
	db, err := openSQLite(src)
	if err != nil {
		return err
	}
	if err := checkpointTruncate(db); err != nil {
		_ = db.Close()
		return err
	}
	if err := db.Close(); err != nil {
		return err
	}
	return copyFile(src, dst)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if fi, err := os.Lstat(dst); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("store: refusing to write through symlink %s", dst)
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chmod(dst, 0o600)
}

func fileExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func lockExclusive(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("store: lock %s: %w", path, err)
	}
	return f, nil
}

func unlockExclusive(f *os.File) {
	if f == nil {
		return
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	_ = f.Close()
}

func readLivePIDs(f *os.File) ([]int, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		pid, err := strconv.Atoi(line)
		if err != nil {
			continue
		}
		if pidAlive(pid) {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

func writePIDs(f *os.File, pids []int) error {
	var b strings.Builder
	for _, pid := range pids {
		fmt.Fprintf(&b, "%d\n", pid)
	}
	if err := f.Truncate(0); err != nil {
		return err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if _, err := f.WriteString(b.String()); err != nil {
		return err
	}
	return f.Sync()
}

func removeOnePID(pids []int, pid int) []int {
	for i, p := range pids {
		if p == pid {
			return append(append([]int{}, pids[:i]...), pids[i+1:]...)
		}
	}
	return pids
}

func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
