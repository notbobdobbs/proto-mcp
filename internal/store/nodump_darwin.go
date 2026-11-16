//go:build darwin

package store

import "golang.org/x/sys/unix"

// hideFromDump marks a working file UF_NODUMP so Time Machine and
// other backup tools that honor the flag skip the plaintext copy.
// Failure is ignored: the flag is a backup hint, not the encryption.
func hideFromDump(path string) {
	_ = unix.Chflags(path, unix.UF_NODUMP)
}
