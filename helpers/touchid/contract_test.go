package touchid_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Issue #125 — the helper must show confirm:true bodies in a scrolling
// alert. LAContext's localizedReason is the macOS dialog title and is
// clipped, so a recipient list that lives only there can hide a BCC
// even after the Go side refused to truncate.
func TestConfirmShowsScrollableAlertBeforeTouchID(t *testing.T) {
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	src, err := os.ReadFile(filepath.Join(filepath.Dir(here), "main.swift"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	for _, want := range []string{
		"req.confirm == true",
		"alert.accessoryView",
		"NSScrollView",
		"NSTextView",
		"hasVerticalScroller = true",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("main.swift missing %q — confirm dialogs would not show the full body", want)
		}
	}
	// The biometric sheet must not be handed the full body. That
	// string is the title on macOS and is where truncation comes back.
	if strings.Contains(s, "localizedReason: req.body") {
		t.Error("localizedReason is req.body; the Touch ID sheet would clip the recipient list")
	}
}
