package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/term"
)

func TestReadMaskedPasswordBackspace(t *testing.T) {
	// "secrX" then backspace, then "et", then enter. The deleted X must
	// not be in the result, and the screen output must be stars plus
	// the erasure sequence — never the typed characters.
	in := bytes.NewReader([]byte("secrX\x7fet\n"))
	var out bytes.Buffer
	got, err := readMaskedPassword(in, &out)
	if err != nil {
		t.Fatalf("readMaskedPassword: %v", err)
	}
	defer zero(got)
	if string(got) != "secret" {
		t.Fatalf("result = %q, want %q", got, "secret")
	}
	shown := out.String()
	for _, c := range "secrXet" {
		if strings.ContainsRune(shown, c) {
			t.Fatalf("output leaked %q in %q", string(c), shown)
		}
	}
	if strings.Count(shown, "*") != len("secrXet") {
		t.Fatalf("star count = %d, output %q", strings.Count(shown, "*"), shown)
	}
	if !strings.Contains(shown, "\b \b") {
		t.Fatalf("output %q, want a backspace erasure", shown)
	}
}

func TestReadMaskedPasswordBSAndEmptyBackspace(t *testing.T) {
	in := bytes.NewReader([]byte("\x7fab\x08\n"))
	var out bytes.Buffer
	got, err := readMaskedPassword(in, &out)
	if err != nil {
		t.Fatalf("readMaskedPassword: %v", err)
	}
	defer zero(got)
	if string(got) != "a" {
		t.Fatalf("result = %q, want %q", got, "a")
	}
	if strings.ContainsAny(out.String(), "ab") {
		t.Fatalf("output leaked typed characters: %q", out.String())
	}
}

func TestReadMaskedPasswordRuneBackspace(t *testing.T) {
	// é is two UTF-8 bytes and one typed character. Backspace removes
	// the whole character and one star.
	in := bytes.NewReader([]byte{0xc3, 0xa9, 0x7f, 'a', '\n'})
	var out bytes.Buffer
	got, err := readMaskedPassword(in, &out)
	if err != nil {
		t.Fatalf("readMaskedPassword: %v", err)
	}
	defer zero(got)
	if string(got) != "a" {
		t.Fatalf("result = %q, want %q", got, "a")
	}
	if strings.Count(out.String(), "*") != 2 {
		t.Fatalf("output %q, want two stars (é and a)", out.String())
	}
	if bytes.Contains(out.Bytes(), []byte{0xc3, 0xa9}) || strings.Contains(out.String(), "a") {
		t.Fatalf("output leaked a character: %q", out.String())
	}
}

func TestReadPasswordNotTerminalDoesNotBlock(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if term.IsTerminal(int(r.Fd())) {
		t.Skip("pipe is a terminal")
	}
	done := make(chan error, 1)
	go func() {
		buf, err := readPassword(r)
		zero(buf)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected the no-echo fallback to fail on a pipe")
		}
	case <-time.After(time.Second):
		t.Fatal("readPassword hung on a non-terminal")
	}
}
