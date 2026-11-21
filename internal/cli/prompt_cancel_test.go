//go:build linux || darwin

package cli

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// Cancelling the password prompt (SIGTERM cancels the process context)
// must restore cooked mode before the tty is closed, and the read must
// return without waiting for Enter.
func TestPromptSecretCancelRestoresTerminal(t *testing.T) {
	_, slave := openPTY(t)
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
}
