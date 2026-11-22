//go:build linux

package cli

import "golang.org/x/sys/unix"

const (
	ioctlReadTermios  = unix.TCGETS
	ioctlWriteTermios = unix.TCSETS
	// Linux defines _POSIX_VDISABLE as NUL. A c_cc slot set to it
	// does not generate a signal.
	posixVDisable byte = 0
)

func disarmQuitAndStop(cc []byte) {
	cc[unix.VQUIT] = posixVDisable
	cc[unix.VSUSP] = posixVDisable
}

func quitAndStopDisarmed(cc []byte) bool {
	return cc[unix.VQUIT] == posixVDisable && cc[unix.VSUSP] == posixVDisable
}
