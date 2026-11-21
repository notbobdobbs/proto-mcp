// Package cli holds small helpers for the protonmcp command-line entry
// points. Right now that's just TTY-aware credential prompts.
package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
	"golang.org/x/term"

	"github.com/just-an-oldsalt/proto-mcp/internal/secret"
)

// ErrNoTTY is returned by the prompt helpers when /dev/tty isn't available
// (e.g. running under a non-interactive launchd session).
var ErrNoTTY = errors.New("no controlling tty available for interactive prompt")

// openTTY opens /dev/tty for read+write. Going direct to /dev/tty
// (instead of os.Stdin) lets the caller still pipe data on stdin
// without confusing the interactive prompts — useful when chaining a
// password manager later.
func openTTY() (*os.File, error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, ErrNoTTY
	}
	return f, nil
}

// watchCancel spawns a goroutine that runs onCancel as soon as ctx is
// cancelled. onCancel must restore a raw terminal before closing the
// tty: closing first makes term.Restore fail on the dead fd and leaves
// the user's shell in raw mode. Closing still has to happen, so the
// in-flight Read returns instead of waiting for Enter.
//
// The watcher exits when stop is closed (the prompt finished normally)
// so it never leaks. Returns a function the prompt must call before
// returning so the goroutine cleans itself up.
func watchCancel(ctx context.Context, onCancel func()) func() {
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			onCancel()
		case <-stop:
		}
	}()
	return func() { close(stop) }
}

// ttyCtl restores raw mode and unblocks a read on cancel. Closing the
// tty from another goroutine does not wake a blocked terminal read
// (and can deadlock the poller), and term.Restore on that closed fd
// fails, so the shell stays raw until Enter. Restore uses a dup of the
// fd. The read polls a wake pipe and returns as soon as cancel writes
// to it.
type ttyCtl struct {
	mu         sync.Mutex
	f          *os.File
	raw        *term.State
	restoreFD  int
	hasRestore bool
	wakeW      *os.File
}

func (c *ttyCtl) enterRaw() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.f == nil {
		return io.ErrClosedPipe
	}
	if !c.hasRestore {
		d, err := unix.Dup(int(c.f.Fd()))
		if err != nil {
			return err
		}
		c.restoreFD = d
		c.hasRestore = true
	}
	st, err := term.MakeRaw(int(c.f.Fd()))
	if err != nil {
		return err
	}
	c.raw = st
	return nil
}

func (c *ttyCtl) restore() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.restoreLocked()
}

func (c *ttyCtl) restoreLocked() {
	if c.raw == nil {
		return
	}
	fd := c.restoreFD
	if !c.hasRestore && c.f != nil {
		fd = int(c.f.Fd())
	}
	if c.hasRestore || c.f != nil {
		_ = term.Restore(fd, c.raw)
	}
	c.raw = nil
}

// cancel restores cooked mode, then wakes the blocked read. The prompt
// fd stays open.
func (c *ttyCtl) cancel() {
	c.mu.Lock()
	c.restoreLocked()
	w := c.wakeW
	c.mu.Unlock()
	if w != nil {
		_, _ = w.Write([]byte{1})
	}
}

// release restores if needed and closes the dup. The caller's file is
// left open.
func (c *ttyCtl) release() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.restoreLocked()
	if c.hasRestore {
		_ = unix.Close(c.restoreFD)
		c.hasRestore = false
	}
}

// PromptLine writes label to /dev/tty and returns the next line of
// input with echo enabled. Trailing CR/LF is stripped. Use for non-
// secret fields (email, TOTP, yes/no answers).
//
// If ctx is cancelled while waiting for input, the tty is closed and
// PromptLine returns ctx.Err() rather than a confusing read error.
func PromptLine(ctx context.Context, label string) (string, error) {
	tty, err := openTTY()
	if err != nil {
		return "", err
	}
	defer tty.Close()
	stop := watchCancel(ctx, func() { _ = tty.Close() })
	defer stop()

	if _, err := io.WriteString(tty, label); err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", err
	}
	r := bufio.NewReader(tty)
	line, err := r.ReadString('\n')
	// Always check ctx first: if the watcher closed the tty, ReadString
	// returns whatever bytes happened to be in the buffer plus io.EOF.
	// Treating that as a clean read would swallow the cancel and let
	// the next prompt run (the "^C at email, falls through to password"
	// UX bug). ctx wins over partial data.
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// errInterrupted is returned by the masked reader when the user types
// Ctrl-C. Raw mode does not turn that byte into SIGINT, so PromptSecret
// raises the signal itself after the terminal is restored.
var errInterrupted = errors.New("interrupted")

// PromptSecret writes label to /dev/tty and reads a line, returning the
// result wrapped in a secret.Secret. On a terminal each typed character
// is shown as '*', and backspace removes one character and one star.
// When the input is not a terminal, it falls back to term.ReadPassword
// (no echo). The read buffer is zeroed before return so the password
// material doesn't sit on the heap waiting for GC.
//
// As with PromptLine, ctx cancellation closes the tty and surfaces
// ctx.Err() — Ctrl-C escapes the prompt cleanly.
func PromptSecret(ctx context.Context, label string) (secret.Secret, error) {
	tty, err := openTTY()
	if err != nil {
		return secret.Secret{}, err
	}
	defer tty.Close()
	return promptSecretTTY(ctx, tty, label)
}

// promptSecretTTY is PromptSecret against an already-open terminal.
// It does not close tty. Cancellation restores cooked mode and unblocks
// the read.
func promptSecretTTY(ctx context.Context, tty *os.File, label string) (secret.Secret, error) {
	wakeR, wakeW, err := os.Pipe()
	if err != nil {
		return secret.Secret{}, err
	}
	defer wakeR.Close()
	defer wakeW.Close()
	ctl := &ttyCtl{f: tty, wakeW: wakeW}
	defer ctl.release()
	stop := watchCancel(ctx, ctl.cancel)
	defer stop()

	if _, err := io.WriteString(tty, label); err != nil {
		if ctx.Err() != nil {
			return secret.Secret{}, ctx.Err()
		}
		return secret.Secret{}, err
	}
	pw, err := readPassword(tty, ctl, wakeR)
	fmt.Fprintln(tty)
	// Same ctx-first rule as PromptLine: closed-tty after cancel can
	// surface as a clean return on some platforms.
	if ctx.Err() != nil {
		zero(pw)
		return secret.Secret{}, ctx.Err()
	}
	if errors.Is(err, errInterrupted) {
		zero(pw)
		// Restore already ran inside readPassword. Raise SIGINT so the
		// process context cancels the same way a cooked-mode Ctrl-C does.
		if p, perr := os.FindProcess(os.Getpid()); perr == nil {
			_ = p.Signal(os.Interrupt)
		}
		select {
		case <-ctx.Done():
		case <-time.After(200 * time.Millisecond):
		}
		if ctx.Err() != nil {
			return secret.Secret{}, ctx.Err()
		}
		return secret.Secret{}, errInterrupted
	}
	if err != nil {
		zero(pw)
		if ctx.Err() != nil {
			return secret.Secret{}, ctx.Err()
		}
		return secret.Secret{}, err
	}
	s := secret.New(pw)
	zero(pw)
	return s, nil
}

// readPassword masks input when fd is a terminal. Otherwise it uses
// term.ReadPassword, the previous no-echo read. MakeRaw failure takes
// the same fallback. ctl.restore runs on the way out, and ctl.close
// (the cancel path) restores before it closes the fd.
func readPassword(tty *os.File, ctl *ttyCtl, wake *os.File) ([]byte, error) {
	fd := int(tty.Fd())
	if !term.IsTerminal(fd) {
		return term.ReadPassword(fd)
	}
	if err := ctl.enterRaw(); err != nil {
		if ctl.f == nil {
			return nil, err
		}
		return term.ReadPassword(fd)
	}
	defer ctl.restore()
	return readMaskedPassword(&ttyReader{fd: fd, wake: int(wake.Fd())}, tty)
}

// errPromptCanceled is the wake-pipe signal. It is not a typed Ctrl-C.
var errPromptCanceled = errors.New("prompt canceled")

// ttyReader reads one byte at a time from a terminal, returning
// errPromptCanceled when the wake pipe becomes readable.
type ttyReader struct {
	fd   int
	wake int
}

func (r *ttyReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	fds := []unix.PollFd{
		{Fd: int32(r.fd), Events: unix.POLLIN},
		{Fd: int32(r.wake), Events: unix.POLLIN},
	}
	for {
		fds[0].Revents = 0
		fds[1].Revents = 0
		_, err := unix.Poll(fds, -1)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if fds[1].Revents != 0 {
			return 0, errPromptCanceled
		}
		if fds[0].Revents&(unix.POLLIN|unix.POLLERR|unix.POLLHUP) == 0 {
			continue
		}
		n, err := unix.Read(r.fd, p[:1])
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return n, err
	}
}

// passwordCap is the initial backing array for a typed secret. Growing
// past it copies into a new array; the old one is zeroed first so the
// abandoned copy does not keep the secret.
const passwordCap = 256

// readMaskedPassword reads a secret from r and writes one '*' to w per
// typed character. Backspace (DEL or BS) deletes the last character and
// erases its star. The returned slice is the caller's to zero; this
// function zeros every other buffer it used.
func readMaskedPassword(r io.Reader, w io.Writer) ([]byte, error) {
	pw := make([]byte, 0, passwordCap)
	var runeLen []int
	var pending []byte
	one := make([]byte, 1)
	defer zero(one)

	finish := func(retErr error) ([]byte, error) {
		zero(pending[:cap(pending)])
		pending = nil
		if retErr != nil {
			zero(pw[:cap(pw)])
			pw = nil
			return nil, retErr
		}
		return pw, nil
	}
	commit := func(p []byte) error {
		need := len(pw) + len(p)
		if need > cap(pw) {
			ncap := cap(pw) * 2
			if ncap < need {
				ncap = need
			}
			next := make([]byte, len(pw), ncap)
			copy(next, pw)
			zero(pw[:cap(pw)])
			pw = next
		}
		pw = append(pw, p...)
		runeLen = append(runeLen, len(p))
		_, err := w.Write([]byte{'*'})
		return err
	}
	backspace := func() error {
		if len(runeLen) == 0 {
			return nil
		}
		n := runeLen[len(runeLen)-1]
		runeLen = runeLen[:len(runeLen)-1]
		for i := len(pw) - n; i < len(pw); i++ {
			pw[i] = 0
		}
		pw = pw[:len(pw)-n]
		_, err := w.Write([]byte("\b \b"))
		return err
	}

	for {
		_, err := r.Read(one)
		if err != nil {
			if err == io.EOF {
				return finish(nil)
			}
			return finish(err)
		}
		b := one[0]
		one[0] = 0

		if len(pending) == 1 && pending[0] == 0x1b && b != '[' && b != 'O' {
			// A bare Esc is not the start of a sequence. Drop it and
			// handle this byte as a normal key so it is not eaten.
			zero(pending)
			pending = nil
		} else if len(pending) > 0 && pending[0] == 0x1b {
			pending = append(pending, b)
			if escapeDone(pending) || len(pending) > 8 {
				zero(pending)
				pending = nil
			}
			continue
		}

		if len(pending) == 0 {
			switch b {
			case '\n', '\r':
				return finish(nil)
			case 0x7f, 0x08:
				if werr := backspace(); werr != nil {
					return finish(werr)
				}
				continue
			case 0x03:
				return finish(errInterrupted)
			case 0x1b:
				pending = append(pending, b)
				continue
			default:
				if b < 0x20 {
					continue
				}
				if b < utf8.RuneSelf {
					chunk := []byte{b}
					werr := commit(chunk)
					zero(chunk)
					if werr != nil {
						return finish(werr)
					}
					continue
				}
				pending = append(pending, b)
			}
		} else {
			pending = append(pending, b)
		}

		if len(pending) == 0 || pending[0] == 0x1b || !utf8.FullRune(pending) {
			continue
		}
		decoded, size := utf8.DecodeRune(pending)
		take := size
		if decoded == utf8.RuneError && size == 1 {
			take = 1
		}
		chunk := append([]byte(nil), pending[:take]...)
		werr := commit(chunk)
		zero(chunk)
		if werr != nil {
			return finish(werr)
		}
		rest := append([]byte(nil), pending[take:]...)
		zero(pending)
		pending = rest
	}
}

// escapeDone reports whether seq is a complete escape sequence (arrows
// and similar). Those bytes are dropped so they never join the secret
// and never appear on screen.
func escapeDone(seq []byte) bool {
	if len(seq) < 2 {
		return false
	}
	switch seq[1] {
	case '[':
		last := seq[len(seq)-1]
		return len(seq) > 2 && last >= 0x40 && last <= 0x7e
	case 'O':
		return len(seq) >= 3
	default:
		// A bare Esc is handled before this. Anything else is not a
		// sequence we swallow.
		return false
	}
}

// zero overwrites b with zeros. Defined here so PromptSecret doesn't
// reach into another package for a three-line loop.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
