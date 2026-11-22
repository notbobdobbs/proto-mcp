//go:build linux || darwin

package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestPTYRawBurst(t *testing.T) {
	master, slave := openPTY(t)
	fd := int(slave.Fd())
	if _, err := makeRawKeepISIG(fd); err != nil {
		t.Fatal(err)
	}
	if err := setNonblock(fd); err != nil {
		t.Fatal(err)
	}
	done := make(chan string, 1)
	go func() {
		pw, err := readMaskedTTY(context.Background(), fd, slave)
		if err != nil {
			done <- "ERR " + err.Error()
			return
		}
		got := string(pw)
		zero(pw)
		done <- got
	}()
	time.Sleep(30 * time.Millisecond)
	if _, err := master.Write([]byte("secrX\x7fet\r")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		if got != "secret" {
			t.Fatalf("got %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

// TestPromptPTYTyping drives the masked prompt from the pty master:
// stars, backspace, CR, LF and Ctrl-D. These bytes have to arrive
// through a blocking read. poll on /dev/tty does not deliver them on macOS.
func TestPromptPTYTyping(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want string
	}{
		{"backspace and CR", []byte("secrX\x7fet\r"), "secret"},
		{"LF", []byte("ab\n"), "ab"},
		{"Ctrl-D", []byte("z\x04"), "z"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			master, slave := openPTY(t)
			type result struct {
				pw  []byte
				err error
			}
			done := make(chan result, 1)
			go func() {
				s, err := promptSecretTTY(context.Background(), slave, "Password: ")
				pw := append([]byte(nil), s.Bytes()...)
				s.Zero()
				done <- result{pw, err}
			}()
			// Drain the prompt text. Leaving it unread makes the
			// backspace echo disturb the input queue.
			waitFor(t, master, "Password:")
			writeAll(t, int(master.Fd()), tt.in)
			var res result
			select {
			case res = <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("prompt did not return after input")
			}
			if res.err != nil {
				t.Fatalf("prompt: %v", res.err)
			}
			if string(res.pw) != tt.want {
				t.Fatalf("password = %q, want %q", res.pw, tt.want)
			}
			for i := range res.pw {
				res.pw[i] = 0
			}
			time.Sleep(20 * time.Millisecond)
			out := readAvailable(master)
			if strings.Contains(out, tt.want) || strings.Contains(out, "secrX") {
				t.Fatalf("terminal showed the secret: %q", out)
			}
			if !strings.Contains(out, "*") {
				t.Fatalf("terminal showed no stars: %q", out)
			}
		})
	}
}

// TestPromptPTYCtrlC writes the Ctrl-C byte to a pty whose foreground
// process group is the prompt. ISIG and VINTR must be set, and the
// other signal characters must be disabled, or the byte would not be
// a kernel SIGINT. kill(SIGINT) is not used: that passes with ISIG off.
func TestPromptPTYCtrlC(t *testing.T) {
	if os.Getenv("PROTONMCP_PROMPT_CHILD") == "1" {
		runPromptCtrlCChild()
		return
	}
	master, slave := openPTY(t)
	path, err := slavePath(slave)
	if err != nil {
		t.Fatalf("slave path: %v", err)
	}
	dupfd, err := unix.Dup(int(slave.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	dup := os.NewFile(uintptr(dupfd), "dup")
	t.Cleanup(func() { _ = dup.Close() })

	cmd := exec.Command(os.Args[0], "-test.run=^TestPromptPTYCtrlC$")
	cmd.Env = append(os.Environ(), "PROTONMCP_PROMPT_CHILD=1", "PROTONMCP_PROMPT_TTY="+path)
	cmd.Stdin = slave
	cmd.Stdout = slave
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	waitFor(t, master, "Password:")
	deadline := time.Now().Add(2 * time.Second)
	var raw *unix.Termios
	for time.Now().Before(deadline) {
		cur, gerr := unix.IoctlGetTermios(dupfd, ioctlReadTermios)
		if gerr == nil && cur.Lflag&unix.ISIG != 0 && cur.Lflag&unix.ICANON == 0 {
			raw = cur
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if raw == nil || raw.Cc[unix.VINTR] != 3 || !quitAndStopDisarmed(raw.Cc[:]) {
		t.Fatalf("raw termios ISIG/VINTR/VQUIT not set for Ctrl-C")
	}
	writeAll(t, int(master.Fd()), []byte{0x03})
	waitErr := make(chan error, 1)
	go func() { waitErr <- cmd.Wait() }()
	select {
	case err := <-waitErr:
		if err != nil {
			t.Fatalf("child exited with error: %v\nstderr: %s", err, stderr.String())
		}
	case <-time.After(3 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("Ctrl-C byte did not cancel the prompt\nstderr: %s", stderr.String())
	}
}

// TestPromptPTYQuitAndStopAreBytes feeds Ctrl-\ and Ctrl-Z (and
// Ctrl-Y, Darwin's delayed-suspend) while the prompt is raw. Those
// slots are _POSIX_VDISABLE, so the bytes must not signal or stop
// the process, and the tty must be cooked again when the prompt ends.
func TestPromptPTYQuitAndStopAreBytes(t *testing.T) {
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGQUIT, syscall.SIGTSTP)
	t.Cleanup(func() { signal.Stop(sigs) })

	master, slave := openPTY(t)
	dupfd, err := unix.Dup(int(slave.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	dup := os.NewFile(uintptr(dupfd), "dup")
	t.Cleanup(func() { _ = dup.Close() })
	before, err := termState(dupfd)
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		pw  []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		s, err := promptSecretTTY(context.Background(), slave, "Password: ")
		pw := append([]byte(nil), s.Bytes()...)
		s.Zero()
		done <- result{pw, err}
	}()
	waitFor(t, master, "Password:")
	deadline := time.Now().Add(2 * time.Second)
	var raw *unix.Termios
	for time.Now().Before(deadline) {
		cur, gerr := unix.IoctlGetTermios(dupfd, ioctlReadTermios)
		if gerr == nil && cur.Lflag&unix.ICANON == 0 && cur.Lflag&unix.ISIG != 0 {
			raw = cur
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if raw == nil {
		t.Fatal("prompt did not enter raw mode")
	}
	if raw.Cc[unix.VINTR] != 3 || !quitAndStopDisarmed(raw.Cc[:]) {
		t.Fatalf("special chars VINTR=%#x VQUIT=%#x VSUSP=%#x, want Ctrl-C only",
			raw.Cc[unix.VINTR], raw.Cc[unix.VQUIT], raw.Cc[unix.VSUSP])
	}
	// 0x1c Ctrl-\, 0x1a Ctrl-Z, 0x19 Ctrl-Y (VDSUSP on Darwin).
	writeAll(t, int(master.Fd()), []byte{0x1c, 0x1a, 0x19, 'p', '\r'})
	var res result
	select {
	case res = <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Ctrl-\\ or Ctrl-Z stopped the prompt")
	}
	select {
	case sig := <-sigs:
		t.Fatalf("byte generated %v", sig)
	default:
	}
	if res.err != nil {
		t.Fatalf("prompt: %v", res.err)
	}
	if string(res.pw) != "p" {
		t.Fatalf("password = %q, want %q", res.pw, "p")
	}
	for i := range res.pw {
		res.pw[i] = 0
	}
	after, err := termState(dupfd)
	if err != nil {
		t.Fatal(err)
	}
	if !termStatesEqual(before, after) {
		t.Fatal("terminal was left in raw mode")
	}
}

func TestPromptPTYSIGHUPRestores(t *testing.T) {
	master, slave := openPTY(t)
	dupfd, err := unix.Dup(int(slave.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	dup := os.NewFile(uintptr(dupfd), "dup")
	t.Cleanup(func() { _ = dup.Close() })
	before, err := termState(dupfd)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := promptSecretTTY(context.Background(), slave, "Password: ")
		done <- err
	}()
	waitFor(t, master, "Password:")
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, errHangup) {
			t.Fatalf("prompt error = %v, want hangup", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SIGHUP left the prompt blocked")
	}
	after, err := termState(dupfd)
	if err != nil {
		t.Fatal(err)
	}
	if !termStatesEqual(before, after) {
		t.Fatal("terminal was left in raw mode after SIGHUP")
	}
}

func runPromptCtrlCChild() {
	if _, err := unix.Setsid(); err != nil && !errors.Is(err, unix.EPERM) {
		fmt.Fprintf(os.Stderr, "setsid: %v\n", err)
		os.Exit(4)
	}
	tty, err := os.OpenFile(os.Getenv("PROTONMCP_PROMPT_TTY"), os.O_RDWR, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open tty: %v\n", err)
		os.Exit(4)
	}
	fd := int(tty.Fd())
	// Opening without O_NOCTTY may already have made this the
	// controlling terminal. Forcing it is required when it did not.
	if err := unix.IoctlSetInt(fd, unix.TIOCSCTTY, 0); err != nil && !errors.Is(err, unix.EPERM) {
		fmt.Fprintf(os.Stderr, "TIOCSCTTY: %v\n", err)
		os.Exit(4)
	}
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPGRP, os.Getpid()); err != nil {
		fmt.Fprintf(os.Stderr, "TIOCSPGRP: %v\n", err)
		os.Exit(5)
	}
	ctx, stop := signalNotifyInterrupt()
	defer stop()
	_, err = promptSecretTTY(ctx, tty, "Password: ")
	if errors.Is(err, context.Canceled) || errors.Is(err, errInterrupted) {
		os.Exit(0)
	}
	fmt.Fprintf(os.Stderr, "prompt: %v\n", err)
	os.Exit(3)
}

func waitFor(t *testing.T, f *os.File, needle string) {
	t.Helper()
	fd := int(f.Fd())
	_ = unix.SetNonblock(fd, true)
	deadline := time.Now().Add(3 * time.Second)
	var buf bytes.Buffer
	tmp := make([]byte, 64)
	for time.Now().Before(deadline) {
		n, err := unix.Read(fd, tmp)
		if n > 0 {
			buf.Write(tmp[:n])
			if strings.Contains(buf.String(), needle) {
				return
			}
			continue
		}
		if err != nil {
			time.Sleep(5 * time.Millisecond)
		}
	}
	t.Fatalf("did not see %q in %q", needle, buf.String())
}

func writeAll(t *testing.T, fd int, p []byte) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for len(p) > 0 && time.Now().Before(deadline) {
		n, err := unix.Write(fd, p)
		if n > 0 {
			p = p[n:]
			continue
		}
		if err != nil {
			time.Sleep(time.Millisecond)
		}
	}
	if len(p) > 0 {
		t.Fatalf("short write, %d bytes left", len(p))
	}
}

func readAvailable(f *os.File) string {
	fd := int(f.Fd())
	_ = unix.SetNonblock(fd, true)
	var buf bytes.Buffer
	tmp := make([]byte, 256)
	deadline := time.Now().Add(50 * time.Millisecond)
	for time.Now().Before(deadline) {
		n, err := unix.Read(fd, tmp)
		if n > 0 {
			buf.Write(tmp[:n])
			continue
		}
		if err != nil {
			time.Sleep(2 * time.Millisecond)
		}
	}
	return buf.String()
}
