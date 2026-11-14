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
	"syscall"
)

// On-disk mirror format (version 1).
//
//	[8]  magic "PMCPENC1"
//	u32  version = 1
//	u32  chunk size (plaintext bytes per chunk)
//	u64  plaintext size
//	repeated chunk:
//	  [12] random nonce
//	  [16] GCM tag
//	  [n]  ciphertext
//
// Each chunk's AAD is the header plus the chunk index and plaintext
// length, so a reordered, truncated, or header-tampered file fails
// authentication. The nonce is random per chunk write; chunks are
// rewritten as a whole, so a rewrite does not reuse a nonce.

const (
	sealMagic     = "PMCPENC1"
	sealVersion   = uint32(1)
	sealChunkSize = 64 * 1024
	sealHeaderLen = 8 + 4 + 4 + 8
)

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

func chunkAAD(header []byte, index uint64, plainLen int) []byte {
	aad := make([]byte, len(header)+8+4)
	copy(aad, header)
	binary.LittleEndian.PutUint64(aad[len(header):], index)
	binary.LittleEndian.PutUint32(aad[len(header)+8:], uint32(plainLen))
	return aad
}

func encodeHeader(plainSize int64) []byte {
	h := make([]byte, sealHeaderLen)
	copy(h, sealMagic)
	binary.LittleEndian.PutUint32(h[8:], sealVersion)
	binary.LittleEndian.PutUint32(h[12:], sealChunkSize)
	binary.LittleEndian.PutUint64(h[16:], uint64(plainSize))
	return h
}

// sealFileAtomic encrypts src and replaces dst. dst is never left as a
// partial ciphertext: the bytes land in dst+".tmp" and are renamed
// over dst only after fsync.
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

	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("store: create %s: %w", tmp, err)
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
		return fmt.Errorf("store: sync %s: %w", tmp, err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("store: close %s: %w", tmp, err)
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return fmt.Errorf("store: chmod %s: %w", tmp, err)
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
	header := encodeHeader(plainSize)
	if _, err := out.Write(header); err != nil {
		return fmt.Errorf("store: write seal header: %w", err)
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
		var nonce [12]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return fmt.Errorf("store: nonce: %w", err)
		}
		sealed := aead.Seal(nil, nonce[:], buf[:n], chunkAAD(header, index, n))
		if len(sealed) != n+aead.Overhead() {
			return fmt.Errorf("store: unexpected ciphertext length %d", len(sealed))
		}
		tag := sealed[n:]
		if _, err := out.Write(nonce[:]); err != nil {
			return err
		}
		if _, err := out.Write(tag); err != nil {
			return err
		}
		if _, err := out.Write(sealed[:n]); err != nil {
			return err
		}
		done += int64(n)
		index++
	}
	return nil
}

// unsealFile decrypts src and replaces dst with the plaintext. On
// authentication failure dst is left untouched.
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

	tmp := dst + ".partial"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("store: create %s: %w", tmp, err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = out.Close()
			_ = os.Remove(tmp)
		}
	}()

	if err := unsealStream(out, in, key, info.Size()); err != nil {
		return err
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

func unsealStream(out io.Writer, in io.Reader, key []byte, fileSize int64) error {
	aead, err := newAEAD(key)
	if err != nil {
		return err
	}
	header := make([]byte, sealHeaderLen)
	if _, err := io.ReadFull(in, header); err != nil {
		return fmt.Errorf("store: read seal header: %w", err)
	}
	if string(header[:8]) != sealMagic {
		return errors.New("store: not an encrypted mirror")
	}
	version := binary.LittleEndian.Uint32(header[8:])
	chunkSize := binary.LittleEndian.Uint32(header[12:])
	plainSize := binary.LittleEndian.Uint64(header[16:])
	if version != sealVersion {
		return fmt.Errorf("store: encrypted mirror version %d, want %d", version, sealVersion)
	}
	if chunkSize != sealChunkSize {
		return fmt.Errorf("store: encrypted mirror chunk size %d, want %d", chunkSize, sealChunkSize)
	}
	// plainSize is not authenticated until the first chunk (or, for an
	// empty file, there is nothing to authenticate — version 1 empty
	// files are header-only). Reject sizes that cannot fit in this file
	// before trusting them for the loop bound. A flipped size still
	// fails GCM because the header is in the AAD.
	if fileSize < sealHeaderLen || plainSize > uint64(fileSize-sealHeaderLen) {
		return errors.New("store: encrypted mirror header is not authentic")
	}

	buf := make([]byte, sealChunkSize)
	var index uint64
	var done uint64
	for done < plainSize {
		var nonce [12]byte
		if _, err := io.ReadFull(in, nonce[:]); err != nil {
			return fmt.Errorf("store: truncated encrypted mirror: %w", err)
		}
		tag := make([]byte, aead.Overhead())
		if _, err := io.ReadFull(in, tag); err != nil {
			return fmt.Errorf("store: truncated encrypted mirror: %w", err)
		}
		n := int(sealChunkSize)
		if remain := plainSize - done; remain < uint64(n) {
			n = int(remain)
		}
		if _, err := io.ReadFull(in, buf[:n]); err != nil {
			return fmt.Errorf("store: truncated encrypted mirror: %w", err)
		}
		sealed := append(append([]byte{}, buf[:n]...), tag...)
		plain, err := aead.Open(nil, nonce[:], sealed, chunkAAD(header, index, n))
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
