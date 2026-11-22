//go:build darwin

package cli

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

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

// reopenTTY opens the same terminal again. The new file description
// is not Go's stdin poller, which keeps a tty read blocking on macOS.
func reopenTTY(fd int) (int, error) {
	buf := make([]byte, 1024)
	_, _, errno := unix.Syscall(unix.SYS_FCNTL, uintptr(fd), uintptr(unix.F_GETPATH), uintptr(unsafe.Pointer(&buf[0])))
	if errno != 0 {
		return -1, errno
	}
	n := 0
	for n < len(buf) && buf[n] != 0 {
		n++
	}
	return unix.Open(string(buf[:n]), unix.O_RDWR|unix.O_NOCTTY, 0)
}
