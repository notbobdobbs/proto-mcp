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
	// Only Ctrl-C stays live. Ctrl-\ (SIGQUIT) can abort and dump core
	// with the password still in memory, and Ctrl-Z (SIGTSTP) stops
	// the process and leaves the tty raw. Darwin also has VDSUSP.
	t.Cc[unix.VINTR] = 3
	disarmQuitAndStop(t.Cc[:])
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

func setNonblock(fd int) error {
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return err
	}
	if flags&unix.O_NONBLOCK != 0 {
		return nil
	}
	_, err = unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags|unix.O_NONBLOCK)
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
	if !(c.hasRestore || c.f != nil) {
		return
	}
	// Drop bytes typed while raw, before cooked echo is turned back on.
	flushInput(fd)
	if err := term.Restore(fd, c.raw); err != nil {
		// Keep c.raw so a later restore can retry.
		return
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
// cooked mode and return without waiting for Enter. The read runs on
// this goroutine and is not left blocked in the kernel.
func promptSecretTTY(ctx context.Context, tty *os.File, label string) (secret.Secret, error) {
	promptCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctl := &ttyCtl{f: tty}
	defer ctl.release()
	// Signals only cancel. The read loop is on this goroutine; it
	// returns through finish (which zeros the password) and then
	// flushes and restores. Restoring from the signal goroutine races
	// the in-flight read.
	stop := watchCancel(promptCtx, func() {
		cancel()
	})
	defer stop()
	stopHUP := watchSignal(syscall.SIGHUP, func() {
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

// ttyReadWait is how long a non-blocking tty read waits before checking
// cancel again. poll and select on /dev/tty do not report input on macOS.
const ttyReadWait = 15 * time.Millisecond

// readPassword masks input when fd is a terminal. Otherwise it uses
// term.ReadPassword, the previous no-echo read. MakeRaw failure takes
// the same fallback.
//
// The masked read runs on this goroutine. The fd is non-blocking;
// EAGAIN sleeps briefly and tries again. Cancel returns through
// finish, which zeros the password before this function returns, so
// nothing stays blocked in unix.Read.
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
	if err := setNonblock(fd); err != nil {
		ctl.restore()
		return nil, err
	}
	defer func() {
		_ = setBlocking(fd)
		ctl.restore()
	}()
	return readMaskedTTY(ctx, fd, tty)
}

// readMaskedTTY reads a secret from a non-blocking tty fd.
func readMaskedTTY(ctx context.Context, fd int, w io.Writer) ([]byte, error) {
	k := newKeyState(w)
	var one [1]byte
	defer zero(one[:])
	for {
		if err := ctx.Err(); err != nil {
			return k.finish(err)
		}
		n, err := unix.Read(fd, one[:])
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			time.Sleep(ttyReadWait)
			continue
		}
		if n == 0 {
			if err == nil || errors.Is(err, io.EOF) {
				return k.finish(nil)
			}
			return k.finish(err)
		}
		b := one[0]
		one[0] = 0
		if done, err := k.byte(b); done || err != nil {
			return k.finish(err)
		}
	}
}

// readMaskedPassword reads a secret from r and writes one '*' to w per
// typed character. Backspace (DEL or BS) deletes the last character and
// erases its star. The returned slice is the caller's to zero; this
// function zeros every other buffer it used.
func readMaskedPassword(r io.Reader, w io.Writer) ([]byte, error) {
	k := newKeyState(w)
	one := make([]byte, 1)
	defer zero(one)
	for {
		n, err := r.Read(one)
		if n == 0 {
			// A zero-length read is EOF even when the error is nil.
			if err == nil || errors.Is(err, io.EOF) {
				return k.finish(nil)
			}
			return k.finish(err)
		}
		b := one[0]
		one[0] = 0
		if done, err := k.byte(b); done || err != nil {
			return k.finish(err)
		}
	}
}

// pendingCap is max(utf8.UTFMax, 8). Escape and UTF-8 bytes are written
// into this array in place so a grow cannot leave a secret in an old
// backing array.
const pendingCap = 8

// passwordCap is the initial backing array for a typed secret. Growing
// past it copies into a new array; the old one is zeroed first so the
// abandoned copy does not keep the secret.
const passwordCap = 256

var (
	starByte = []byte{'*'}
	eraseSeq = []byte{'\b', ' ', '\b'}
)

// keyState is the masked-input state machine. byte reports done when
// the line is finished.
type keyState struct {
	pw      []byte
	runeLen []int
	pending [pendingCap]byte
	npend   int
	w       io.Writer
}

func newKeyState(w io.Writer) *keyState {
	return &keyState{
		pw:      make([]byte, 0, passwordCap),
		runeLen: make([]int, 0, 64),
		w:       w,
	}
}

func (k *keyState) finish(retErr error) ([]byte, error) {
	k.clearPending()
	if retErr != nil {
		zero(k.pw[:cap(k.pw)])
		k.pw = nil
		return nil, retErr
	}
	return k.pw, nil
}

func (k *keyState) clearPending() {
	for i := 0; i < k.npend; i++ {
		k.pending[i] = 0
	}
	k.npend = 0
}

func (k *keyState) commitByte(b byte) error {
	if len(k.pw)+1 > cap(k.pw) {
		ncap := cap(k.pw) * 2
		if ncap < len(k.pw)+1 {
			ncap = len(k.pw) + 1
		}
		next := make([]byte, len(k.pw), ncap)
		copy(next, k.pw)
		zero(k.pw[:cap(k.pw)])
		k.pw = next
	}
	k.pw = append(k.pw, b)
	k.runeLen = append(k.runeLen, 1)
	_, err := k.w.Write(starByte)
	return err
}

func (k *keyState) commitCopy(p []byte) error {
	if len(k.pw)+len(p) > cap(k.pw) {
		ncap := cap(k.pw) * 2
		if ncap < len(k.pw)+len(p) {
			ncap = len(k.pw) + len(p)
		}
		next := make([]byte, len(k.pw), ncap)
		copy(next, k.pw)
		zero(k.pw[:cap(k.pw)])
		k.pw = next
	}
	k.pw = append(k.pw, p...)
	k.runeLen = append(k.runeLen, len(p))
	_, err := k.w.Write(starByte)
	return err
}

func (k *keyState) backspace() error {
	if len(k.runeLen) == 0 {
		return nil
	}
	n := k.runeLen[len(k.runeLen)-1]
	k.runeLen = k.runeLen[:len(k.runeLen)-1]
	for i := len(k.pw) - n; i < len(k.pw); i++ {
		k.pw[i] = 0
	}
	k.pw = k.pw[:len(k.pw)-n]
	_, err := k.w.Write(eraseSeq)
	return err
}

// byte handles one input byte. done is true when the line is complete.
func (k *keyState) byte(b byte) (bool, error) {
	if k.npend > 0 || b == 0x1b || b >= utf8.RuneSelf {
		handled, err := k.accept(b)
		if err != nil || handled {
			return false, err
		}
	}
	switch b {
	case '\n', '\r', 0x04:
		return true, nil
	case 0x7f, 0x08:
		return false, k.backspace()
	case 0x03:
		return true, errInterrupted
	default:
		if b < 0x20 || b >= utf8.RuneSelf {
			return false, nil
		}
		return false, k.commitByte(b)
	}
}

// accept handles Esc sequences and UTF-8 tails. It reports handled when
// b is not an ordinary ASCII key. A bad UTF-8 lead (RuneError, 1) is
// dropped and b is left for the main key switch, so Enter and backspace
// after a stray 0xc3 still work.
func (k *keyState) accept(b byte) (bool, error) {
	if k.npend > 0 && k.pending[0] == 0x1b {
		if k.npend == 1 && b != '[' && b != 'O' {
			k.clearPending()
			return false, nil
		}
		if k.npend >= len(k.pending) {
			k.clearPending()
			return true, nil
		}
		k.pending[k.npend] = b
		k.npend++
		if escapeDone(k.pending[:k.npend]) || k.npend > 8 {
			k.clearPending()
		}
		return true, nil
	}
	if b == 0x1b && k.npend == 0 {
		k.pending[0] = b
		k.npend = 1
		return true, nil
	}
	if k.npend > 0 {
		if k.npend >= len(k.pending) {
			k.clearPending()
			return false, nil
		}
		var trial [pendingCap]byte
		copy(trial[:], k.pending[:k.npend])
		trial[k.npend] = b
		seq := trial[:k.npend+1]
		if !utf8.FullRune(seq) && len(seq) < utf8.UTFMax {
			k.pending[k.npend] = b
			k.npend++
			return true, nil
		}
		r, size := utf8.DecodeRune(seq)
		if r == utf8.RuneError && size == 1 {
			k.clearPending()
			return false, nil
		}
		if err := k.commitCopy(seq[:size]); err != nil {
			return true, err
		}
		k.clearPending()
		if size < len(seq) && seq[len(seq)-1] == b && size == len(seq)-1 {
			return false, nil
		}
		if size < len(seq) {
			copy(k.pending[:], seq[size:])
			k.npend = len(seq) - size
		}
		return true, nil
	}
	if b >= utf8.RuneSelf {
		k.pending[0] = b
		k.npend = 1
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
