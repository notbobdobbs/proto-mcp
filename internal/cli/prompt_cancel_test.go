//go:build linux || darwin

package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// Cancelling the password prompt (SIGTERM cancels the process context)
// must restore cooked mode before the tty is closed, and the read must
// return without waiting for Enter.
func TestPromptSecretCancelRestoresTerminal(t *testing.T) {
	master, slave := openPTY(t)
	dupfd, err := unix.Dup(int(slave.Fd()))
	if err != nil {
		t.Fatalf("dup slave: %v", err)
	}
	dup := os.NewFile(uintptr(dupfd), "pty-slave-dup")
	t.Cleanup(func() { _ = dup.Close() })

	before, err := term.GetState(dupfd)
	if err != nil {
		t.Fatalf("termios before: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type result struct{ err error }
	done := make(chan result, 1)
	go func() {
		_, err := promptSecretTTY(ctx, slave, "Password: ")
		done <- result{err}
	}()

	deadline := time.Now().Add(2 * time.Second)
	raw := false
	for time.Now().Before(deadline) {
		cur, gerr := term.GetState(dupfd)
		if gerr == nil && !reflect.DeepEqual(before, cur) {
			raw = true
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !raw {
		t.Fatal("password prompt did not enter raw mode")
	}

	cancel()
	select {
	case res := <-done:
		if !errors.Is(res.err, context.Canceled) {
			t.Fatalf("prompt error = %v, want context.Canceled", res.err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancel left the password prompt blocked")
	}

	after, err := term.GetState(dupfd)
	if err != nil {
		t.Fatalf("termios after cancel: %v", err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("terminal was left in raw mode after cancel")
	}
	// The prompt must not still be reading the tty. A later line has
	// to arrive intact, including its echo, for the next prompt.
	if _, err := master.Write([]byte("next-line\n")); err != nil {
		t.Fatal(err)
	}
	_ = unix.SetNonblock(int(slave.Fd()), true)
	deadline = time.Now().Add(time.Second)
	var got bytes.Buffer
	tmp := make([]byte, 64)
	for time.Now().Before(deadline) && !strings.Contains(got.String(), "next-line") {
		n, rerr := unix.Read(int(slave.Fd()), tmp)
		if n > 0 {
			got.Write(tmp[:n])
			continue
		}
		if rerr != nil {
			time.Sleep(5 * time.Millisecond)
		}
	}
	if !strings.Contains(got.String(), "next-line") {
		t.Fatalf("next reader got %q", got.String())
	}
}
