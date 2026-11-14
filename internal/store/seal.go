package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// On-disk mirror format (version 2).
//
//	[8]  magic "PMCPENC2"
//	u32  version = 2
//	u32  chunk size
//	u64  plaintext size
//	[12] header nonce
//	[16] snapshot id (GCM plaintext; random per seal)
//	[16] header tag over that id, bound to the prefix
//	repeated chunk:
//	  [12] random nonce
//	  [16] GCM tag
//	  [n]  ciphertext
//
// The header tag authenticates the size and the snapshot id, including
// when the plaintext is empty. A short or zeroed header therefore fails
// closed and is never renamed over an existing mirror. Each chunk's
// AAD is the snapshot id, the chunk index, and the chunk's plaintext
// length, so a chunk from another snapshot cannot be spliced in even
// when the two plaintexts have the same size.

const (
	sealMagic       = "PMCPENC2"
	sealVersion     = uint32(2)
	sealChunkSize   = 64 * 1024
	sealPrefixLen   = 8 + 4 + 4 + 8 // magic, version, chunk size, plain size
	sealSnapshotLen = 16
	sealNonceLen    = 12
	sealTagLen      = 16
	sealHeaderLen   = sealPrefixLen + sealSnapshotLen + sealNonceLen + sealTagLen
)

type sealHeader struct {
	prefix     []byte
	snapshotID [sealSnapshotLen]byte
	plainSize  uint64
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("store: encryption key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func chunkAAD(snapshotID []byte, index uint64, plainLen int) []byte {
	aad := make([]byte, len(snapshotID)+8+4)
	copy(aad, snapshotID)
	binary.LittleEndian.PutUint64(aad[len(snapshotID):], index)
	binary.LittleEndian.PutUint32(aad[len(snapshotID)+8:], uint32(plainLen))
	return aad
}

// exclusiveTemp creates a new file in dir (which must be mode 0700)
// with O_EXCL|O_NOFOLLOW. It never truncates an existing path.
func exclusiveTemp(dir, prefix string) (*os.File, string, error) {
	if err := ensureOwnerOnlyDir(dir); err != nil {
		return nil, "", err
	}
	for range 100 {
		var rnd [8]byte
		if _, err := rand.Read(rnd[:]); err != nil {
			return nil, "", err
		}
		name := filepath.Join(dir, fmt.Sprintf(".%s.%d.%x", prefix, os.Getpid(), rnd))
		f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return nil, "", fmt.Errorf("store: create temp in %s: %w", dir, err)
		}
		return f, name, nil
	}
	return nil, "", errors.New("store: could not create an exclusive temp file")
}

func ensureOwnerOnlyDir(dir string) error {
	if dir == "" || dir == "." {
		return errors.New("store: refusing to seal into the current directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("store: create %s: %w", dir, err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("store: chmod %s: %w", dir, err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		return fmt.Errorf("store: %s must be a directory with mode 0700", dir)
	}
	return nil
}

// sealFileAtomic encrypts src and replaces dst only after the whole
// ciphertext is fsynced. A failure leaves dst untouched. The temp file
// is created with O_EXCL|O_NOFOLLOW in a 0700 directory.
func sealFileAtomic(dst, src string, key []byte) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("store: open %s for seal: %w", src, err)
	}
	defer in.Close()
	fi, err := in.Stat()
	if err != nil {
		return fmt.Errorf("store: stat %s: %w", src, err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("store: %s is not a regular file", src)
	}

	out, tmp, err := exclusiveTemp(filepath.Dir(dst), "seal")
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			_ = out.Close()
			_ = os.Remove(tmp)
		}
	}()

	if err := sealStream(out, in, key, fi.Size()); err != nil {
		return err
	}
	if err := out.Sync(); err != nil {
		return fmt.Errorf("store: sync sealed temp: %w", err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("store: close sealed temp: %w", err)
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		return fmt.Errorf("store: rename sealed mirror: %w", err)
	}
	ok = true
	return nil
}

func sealStream(out io.Writer, in io.Reader, key []byte, plainSize int64) error {
	aead, err := newAEAD(key)
	if err != nil {
		return err
	}
	if plainSize < 0 {
		return fmt.Errorf("store: negative plaintext size %d", plainSize)
	}
	var snapshotID [sealSnapshotLen]byte
	if _, err := rand.Read(snapshotID[:]); err != nil {
		return fmt.Errorf("store: snapshot id: %w", err)
	}
	prefix := make([]byte, sealPrefixLen)
	copy(prefix, sealMagic)
	binary.LittleEndian.PutUint32(prefix[8:], sealVersion)
	binary.LittleEndian.PutUint32(prefix[12:], sealChunkSize)
	binary.LittleEndian.PutUint64(prefix[16:], uint64(plainSize))

	var nonce [sealNonceLen]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("store: header nonce: %w", err)
	}
	// Authenticate the prefix and the snapshot id. Empty plaintext
	// still has this tag, so a zeroed header does not verify.
	mac := aead.Seal(nil, nonce[:], snapshotID[:], prefix)
	if len(mac) != sealSnapshotLen+sealTagLen {
		return fmt.Errorf("store: unexpected header tag length %d", len(mac))
	}
	if _, err := out.Write(prefix); err != nil {
		return fmt.Errorf("store: write seal header: %w", err)
	}
	if _, err := out.Write(nonce[:]); err != nil {
		return err
	}
	if _, err := out.Write(mac); err != nil {
		return err
	}

	buf := make([]byte, sealChunkSize)
	var index uint64
	var done int64
	for done < plainSize {
		want := sealChunkSize
		if remain := plainSize - done; remain < int64(want) {
			want = int(remain)
		}
		n, err := io.ReadFull(in, buf[:want])
		if err != nil {
			return fmt.Errorf("store: read plaintext: %w", err)
		}
		var cnonce [sealNonceLen]byte
		if _, err := rand.Read(cnonce[:]); err != nil {
			return fmt.Errorf("store: nonce: %w", err)
		}
		sealed := aead.Seal(nil, cnonce[:], buf[:n], chunkAAD(snapshotID[:], index, n))
		if len(sealed) != n+aead.Overhead() {
			return fmt.Errorf("store: unexpected ciphertext length %d", len(sealed))
		}
		if _, err := out.Write(cnonce[:]); err != nil {
			return err
		}
		if _, err := out.Write(sealed[n:]); err != nil {
			return err
		}
		if _, err := out.Write(sealed[:n]); err != nil {
			return err
		}
		done += int64(n)
		index++
		clear(buf[:n])
	}
	return nil
}

// unsealFile decrypts src onto dst. The header is authenticated before
// any output file is created. On failure dst is left untouched and src
// is not removed.
func unsealFile(dst, src string, key []byte) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("store: open %s: %w", src, err)
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	hdr, err := readAndVerifyHeader(in, key, info.Size())
	if err != nil {
		return err
	}

	out, tmp, err := exclusiveTemp(filepath.Dir(dst), "unseal")
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			_ = out.Close()
			_ = os.Remove(tmp)
		}
	}()
	if err := unsealChunks(out, in, key, hdr); err != nil {
		return err
	}
	var extra [1]byte
	if n, err := in.Read(extra[:]); n > 0 || (err != nil && !errors.Is(err, io.EOF)) {
		if err == nil {
			err = errors.New("trailing bytes")
		}
		return fmt.Errorf("store: encrypted mirror has trailing data: %w", err)
	}
	if err := out.Sync(); err != nil {
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		return fmt.Errorf("store: rename working copy: %w", err)
	}
	ok = true
	return nil
}

func readAndVerifyHeader(in io.Reader, key []byte, fileSize int64) (sealHeader, error) {
	if fileSize < sealHeaderLen {
		return sealHeader{}, errors.New("store: encrypted mirror header is truncated")
	}
	aead, err := newAEAD(key)
	if err != nil {
		return sealHeader{}, err
	}
	prefix := make([]byte, sealPrefixLen)
	if _, err := io.ReadFull(in, prefix); err != nil {
		return sealHeader{}, errors.New("store: encrypted mirror header is truncated")
	}
	if string(prefix[:8]) != sealMagic {
		return sealHeader{}, errors.New("store: not an encrypted mirror")
	}
	version := binary.LittleEndian.Uint32(prefix[8:])
	chunkSize := binary.LittleEndian.Uint32(prefix[12:])
	plainSize := binary.LittleEndian.Uint64(prefix[16:])
	if version != sealVersion {
		return sealHeader{}, fmt.Errorf("store: encrypted mirror version %d, want %d", version, sealVersion)
	}
	if chunkSize != sealChunkSize {
		return sealHeader{}, fmt.Errorf("store: encrypted mirror chunk size %d, want %d", chunkSize, sealChunkSize)
	}
	// A claimed size that cannot fit in this file is rejected before
	// we trust it. The header tag then authenticates the size, so a
	// zeroed or shortened header cannot verify.
	if plainSize > uint64(fileSize-sealHeaderLen) {
		return sealHeader{}, errors.New("store: encrypted mirror header is not authentic")
	}
	var nonce [sealNonceLen]byte
	if _, err := io.ReadFull(in, nonce[:]); err != nil {
		return sealHeader{}, errors.New("store: encrypted mirror header is truncated")
	}
	mac := make([]byte, sealSnapshotLen+sealTagLen)
	if _, err := io.ReadFull(in, mac); err != nil {
		return sealHeader{}, errors.New("store: encrypted mirror header is truncated")
	}
	opened, err := aead.Open(nil, nonce[:], mac, prefix)
	if err != nil || len(opened) != sealSnapshotLen {
		return sealHeader{}, errors.New("store: encrypted mirror failed authentication (wrong key or tampered file)")
	}
	var hdr sealHeader
	hdr.prefix = prefix
	copy(hdr.snapshotID[:], opened)
	hdr.plainSize = plainSize
	return hdr, nil
}

func unsealChunks(out io.Writer, in io.Reader, key []byte, hdr sealHeader) error {
	aead, err := newAEAD(key)
	if err != nil {
		return err
	}
	buf := make([]byte, sealChunkSize)
	var index uint64
	var done uint64
	for done < hdr.plainSize {
		var nonce [sealNonceLen]byte
		if _, err := io.ReadFull(in, nonce[:]); err != nil {
			return fmt.Errorf("store: truncated encrypted mirror: %w", err)
		}
		tag := make([]byte, aead.Overhead())
		if _, err := io.ReadFull(in, tag); err != nil {
			return fmt.Errorf("store: truncated encrypted mirror: %w", err)
		}
		n := int(sealChunkSize)
		if remain := hdr.plainSize - done; remain < uint64(n) {
			n = int(remain)
		}
		if _, err := io.ReadFull(in, buf[:n]); err != nil {
			return fmt.Errorf("store: truncated encrypted mirror: %w", err)
		}
		sealed := append(append([]byte{}, buf[:n]...), tag...)
		plain, err := aead.Open(nil, nonce[:], sealed, chunkAAD(hdr.snapshotID[:], index, n))
		if err != nil {
			return errors.New("store: encrypted mirror failed authentication (wrong key or tampered file)")
		}
		if _, err := out.Write(plain); err != nil {
			return err
		}
		done += uint64(len(plain))
		index++
		clear(buf[:n])
	}
	return nil
}

// shred overwrites a regular file with random bytes and removes it.
// Symlinks are refused so a planted link cannot redirect the overwrite
// onto another file. A missing path is not an error.
//
// This is best-effort. APFS and other copy-on-write filesystems do not
// guarantee the old extents are gone; the point is to drop the
// directory entry and not leave a trivially readable plaintext file
// behind when the sealed copy has replaced it.
func shred(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("store: stat %s: %w", path, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("store: refusing to shred symlink %s", path)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("store: refusing to shred non-regular file %s", path)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("store: open %s for shred: %w", path, err)
	}
	defer f.Close()

	buf := make([]byte, 64*1024)
	var written int64
	for written < fi.Size() {
		if _, err := rand.Read(buf); err != nil {
			return fmt.Errorf("store: shred %s: %w", path, err)
		}
		n := int64(len(buf))
		if remain := fi.Size() - written; remain < n {
			n = remain
		}
		if _, err := f.Write(buf[:n]); err != nil {
			return fmt.Errorf("store: shred %s: %w", path, err)
		}
		written += n
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("store: shred %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("store: remove %s: %w", path, err)
	}
	return nil
}

func isSQLiteFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var magic [16]byte
	n, _ := io.ReadFull(f, magic[:])
	return n == 16 && string(magic[:]) == "SQLite format 3\x00"
}

func isSealedFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var magic [8]byte
	n, _ := io.ReadFull(f, magic[:])
	return n == 8 && string(magic[:]) == sealMagic
}
