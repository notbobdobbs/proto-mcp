//go:build linux

package cli

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

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

// flushInput drops unread tty input. TCIFLUSH is 0; x/sys does not
// export that selector.
func flushInput(fd int) {
	_ = unix.IoctlSetInt(fd, unix.TCFLSH, 0)
}

// reopenTTY opens the same terminal again. The new file description
// is not Go's stdin poller, which keeps a tty read blocking on macOS.
func reopenTTY(fd int) (int, error) {
	path, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return -1, err
	}
	// Blocking open. VMIN 0 / VTIME makes the read time out. O_NONBLOCK
	// on this pty makes macOS ignore that timer and still block.
	return unix.Open(path, unix.O_RDWR|unix.O_NOCTTY, 0)
}
