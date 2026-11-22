//go:build darwin

package cli

import "golang.org/x/sys/unix"

const (
	ioctlReadTermios  = unix.TIOCGETA
	ioctlWriteTermios = unix.TIOCSETA
	// Darwin defines _POSIX_VDISABLE as 0xff.
	posixVDisable byte = 0xff
)

func disarmQuitAndStop(cc []byte) {
	cc[unix.VQUIT] = posixVDisable
	cc[unix.VSUSP] = posixVDisable
	cc[unix.VDSUSP] = posixVDisable
}

func quitAndStopDisarmed(cc []byte) bool {
	return cc[unix.VQUIT] == posixVDisable &&
		cc[unix.VSUSP] == posixVDisable &&
		cc[unix.VDSUSP] == posixVDisable
}

// flushInput drops unread tty input. FREAD (1) selects the input queue.
func flushInput(fd int) {
	_ = unix.IoctlSetPointerInt(fd, unix.TIOCFLUSH, 1)
}
