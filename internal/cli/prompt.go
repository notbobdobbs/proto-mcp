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
	"os/signal"
	"strings"
	"sync"
	"syscall"
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
// cancelled. For the password prompt, onCancel restores cooked mode
// and does not close the tty: closing does not wake a blocked read,
// and term.Restore on a closed fd leaves the shell raw. PromptLine
// still closes its tty so bufio's read returns.
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

// ttyCtl restores raw mode from a dup of the tty fd. Closing the tty
// from another goroutine does not wake a blocked terminal read, and
// term.Restore on that closed fd fails, so the shell stays raw until
// Enter. The dup stays open for the restore.
type ttyCtl struct {
	mu         sync.Mutex
	f          *os.File
	raw        *term.State
	restoreFD  int
	hasRestore bool
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
	fd := int(c.f.Fd())
	st, err := makeRawKeepISIG(fd)
	if err != nil {
		return err
	}
	if err := setBlocking(fd); err != nil {
		_ = term.Restore(fd, st)
		return err
	}
	c.raw = st
	return nil
}

// makeRawKeepISIG is term.MakeRaw without clearing ISIG, in one
// termios update. A second update flushes bytes that arrived between
// the two calls. ISIG stays on so Ctrl+C is a kernel SIGINT. On macOS
// the masked read never observed the 0x03 byte, and with ISIG off the
// signal was not delivered either.
func makeRawKeepISIG(fd int) (*term.State, error) {
	old, err := term.GetState(fd)
	if err != nil {
		return nil, err
	}
	t, err := unix.IoctlGetTermios(fd, ioctlReadTermios)
	if err != nil {
		return nil, err
	}
	t.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	t.Oflag &^= unix.OPOST
	t.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.IEXTEN
	t.Lflag |= unix.ISIG
	t.Cflag &^= unix.CSIZE | unix.PARENB
	t.Cflag |= unix.CS8
	t.Cc[unix.VINTR] = 3
	t.Cc[unix.VMIN] = 1
	t.Cc[unix.VTIME] = 0
	if err := unix.IoctlSetTermios(fd, ioctlWriteTermios, t); err != nil {
		return nil, err
	}
	return old, nil
}

func setBlocking(fd int) error {
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return err
	}
	if flags&unix.O_NONBLOCK == 0 {
		return nil
	}
	_, err = unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags&^unix.O_NONBLOCK)
	return err
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

// errInterrupted is returned when a raw read actually receives 0x03.
// With ISIG left on, a real terminal turns Ctrl+C into SIGINT instead,
// and the prompt returns via ctx. PromptSecret still raises SIGINT if
// the byte shows up, so both paths cancel the process.
var errInterrupted = errors.New("interrupted")

// errHangup is returned when SIGHUP arrives during the password prompt.
// The terminal is restored first.
var errHangup = errors.New("hangup")

// PromptSecret writes label to /dev/tty and reads a line, returning the
// result wrapped in a secret.Secret. On a terminal each typed character
// is shown as '*', and backspace removes one character and one star.
// When the input is not a terminal, it falls back to term.ReadPassword
// (no echo). The read buffer is zeroed before return so the password
// material doesn't sit on the heap waiting for GC.
//
// SIGINT, SIGTERM and SIGHUP restore cooked mode and return ctx.Err()
// or a hangup error without waiting for Enter. Ctrl-C is a kernel
// SIGINT because raw mode leaves ISIG on.
func PromptSecret(ctx context.Context, label string) (secret.Secret, error) {
	tty, err := openTTY()
	if err != nil {
		return secret.Secret{}, err
	}
	defer tty.Close()
	return promptSecretTTY(ctx, tty, label)
}

// promptSecretTTY is PromptSecret against an already-open terminal.
// It does not close tty. SIGTERM (ctx), SIGINT and SIGHUP restore
// cooked mode and return without waiting for Enter. A read still
// blocked in the kernel is discarded and zeroed when it eventually
// returns; it is not waited on.
func promptSecretTTY(ctx context.Context, tty *os.File, label string) (secret.Secret, error) {
	promptCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctl := &ttyCtl{f: tty}
	defer ctl.release()
	stop := watchCancel(promptCtx, func() {
		ctl.restore()
		cancel()
	})
	defer stop()
	stopHUP := watchSignal(syscall.SIGHUP, func() {
		ctl.restore()
		cancel()
	})
	defer stopHUP()
	// Ctrl-C is SIGINT from the tty. A raw read does not see the byte.
	// Record it separately from SIGHUP: both cancel the local context,
	// and a local-only cancel would otherwise look like a hangup.
	interrupted := make(chan struct{}, 1)
	stopINT := watchSignal(syscall.SIGINT, func() {
		select {
		case interrupted <- struct{}{}:
		default:
		}
		ctl.restore()
		cancel()
	})
	defer stopINT()

	if _, err := io.WriteString(tty, label); err != nil {
		if ctx.Err() != nil {
			return secret.Secret{}, ctx.Err()
		}
		return secret.Secret{}, err
	}
	pw, err := readPassword(promptCtx, tty, ctl)
	fmt.Fprintln(tty)
	// Same ctx-first rule as PromptLine: closed-tty after cancel can
	// surface as a clean return on some platforms.
	if ctx.Err() != nil {
		zero(pw)
		return secret.Secret{}, ctx.Err()
	}
	select {
	case <-interrupted:
		zero(pw)
		return secret.Secret{}, errInterrupted
	default:
	}
	if errors.Is(err, errHangup) || (promptCtx.Err() != nil && ctx.Err() == nil) {
		zero(pw)
		return secret.Secret{}, errHangup
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

// watchSignal invokes onSignal for one signal, then ignores it. SIGHUP
// is not on the process-wide NotifyContext: serve-stdio uses it to
// reload policy. The password prompt watches SIGHUP and SIGINT only
// while the prompt is up, so the shell is not left raw if the session
// drops or the user hits Ctrl-C.
func watchSignal(sig os.Signal, onSignal func()) func() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, sig)
	stop := make(chan struct{})
	go func() {
		select {
		case <-ch:
			onSignal()
		case <-stop:
		}
	}()
	return func() {
		signal.Stop(ch)
		close(stop)
	}
}

// readPassword masks input when fd is a terminal. Otherwise it uses
// term.ReadPassword, the previous no-echo read. MakeRaw failure takes
// the same fallback.
//
// Keystrokes are blocking unix.Read calls, the same shape as
// golang.org/x/term ReadPassword. poll/select on /dev/tty does not
// report input on macOS, so the mask must not wait that way. Cancel
// restores the terminal and returns; a read that completes later is
// discarded and zeroed.
func readPassword(ctx context.Context, tty *os.File, ctl *ttyCtl) ([]byte, error) {
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

	type result struct {
		pw  []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		pw, err := readMaskedPassword(blockingFD(fd), tty)
		done <- result{pw, err}
	}()
	select {
	case r := <-done:
		if ctx.Err() != nil {
			zero(r.pw)
			return nil, ctx.Err()
		}
		return r.pw, r.err
	case <-ctx.Done():
		ctl.restore()
		go func() {
			r := <-done
			zero(r.pw)
		}()
		return nil, ctx.Err()
	}
}

// blockingFD is a one-byte unix.Read. A zero-length read is EOF.
type blockingFD int

func (f blockingFD) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		n, err := unix.Read(int(f), p[:1])
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if n == 0 && err == nil {
			return 0, io.EOF
		}
		return n, err
	}
}

type secretBufs struct {
	pw      []byte
	idx     []int
	pending []byte
}

func newSecretBufs() *secretBufs {
	return &secretBufs{
		pw:      make([]byte, 0, passwordCap),
		idx:     make([]int, 0, 64),
		pending: make([]byte, 0, utf8.UTFMax),
	}
}

// passwordCap is the initial backing array for a typed secret. Growing
// past it copies into a new array; the old one is zeroed first so the
// abandoned copy does not keep the secret.
const passwordCap = 256

var (
	starByte = []byte{'*'}
	eraseSeq = []byte{'\b', ' ', '\b'}
)

// readMaskedPassword reads a secret from r and writes one '*' to w per
// typed character. Backspace (DEL or BS) deletes the last character and
// erases its star. The returned slice is the caller's to zero; this
// function zeros every other buffer it used.
func readMaskedPassword(r io.Reader, w io.Writer) ([]byte, error) {
	// Heap buffers so growing the password can zero the abandoned array.
	hold := newSecretBufs()
	pw := hold.pw
	runeLen := hold.idx
	pending := hold.pending
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
	commitByte := func(b byte) error {
		if len(pw)+1 > cap(pw) {
			ncap := cap(pw) * 2
			if ncap < len(pw)+1 {
				ncap = len(pw) + 1
			}
			next := make([]byte, len(pw), ncap)
			copy(next, pw)
			zero(pw[:cap(pw)])
			pw = next
		}
		pw = append(pw, b)
		runeLen = append(runeLen, 1)
		_, err := w.Write(starByte)
		return err
	}
	commitCopy := func(p []byte) error {
		if len(pw)+len(p) > cap(pw) {
			ncap := cap(pw) * 2
			if ncap < len(pw)+len(p) {
				ncap = len(pw) + len(p)
			}
			next := make([]byte, len(pw), ncap)
			copy(next, pw)
			zero(pw[:cap(pw)])
			pw = next
		}
		pw = append(pw, p...)
		runeLen = append(runeLen, len(p))
		_, err := w.Write(starByte)
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
		_, err := w.Write(eraseSeq)
		return err
	}

	for {
		n, err := r.Read(one)
		if n == 0 {
			// A zero-length read is EOF even when the error is nil.
			if err == nil || errors.Is(err, io.EOF) {
				return finish(nil)
			}
			return finish(err)
		}
		b := one[0]
		one[0] = 0
		if len(pending) > 0 || b == 0x1b || b >= utf8.RuneSelf {
			handled, err := acceptByte(&pending, b, commitCopy)
			if err != nil {
				return finish(err)
			}
			if handled {
				continue
			}
		}
		switch b {
		case '\n', '\r', 0x04:
			return finish(nil)
		case 0x7f, 0x08:
			if werr := backspace(); werr != nil {
				return finish(werr)
			}
		case 0x03:
			return finish(errInterrupted)
		default:
			if b < 0x20 || b >= utf8.RuneSelf {
				continue
			}
			if werr := commitByte(b); werr != nil {
				return finish(werr)
			}
		}
	}
}

// acceptByte handles Esc sequences and UTF-8 tails. It reports handled
// when b is not an ordinary ASCII key. The ASCII path stays in the
// caller so a pty read cannot drop those bytes.
func acceptByte(pending *[]byte, b byte, commitCopy func([]byte) error) (bool, error) {
	p := *pending
	if len(p) > 0 && p[0] == 0x1b {
		if len(p) == 1 && b != '[' && b != 'O' {
			zero(p)
			*pending = nil
			return false, nil
		}
		p = append(p, b)
		if escapeDone(p) || len(p) > 8 {
			zero(p)
			*pending = nil
			return true, nil
		}
		*pending = p
		return true, nil
	}
	if b == 0x1b {
		*pending = []byte{b}
		return true, nil
	}
	if len(p) > 0 {
		p = append(p, b)
		if !utf8.FullRune(p) && len(p) < utf8.UTFMax {
			*pending = p
			return true, nil
		}
		r, size := utf8.DecodeRune(p)
		take := size
		if r == utf8.RuneError && size == 1 {
			take = 1
		}
		if err := commitCopy(p[:take]); err != nil {
			return true, err
		}
		rest := append([]byte(nil), p[take:]...)
		zero(p)
		*pending = rest
		return true, nil
	}
	if b >= utf8.RuneSelf {
		*pending = []byte{b}
		return true, nil
	}
	return false, nil
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
