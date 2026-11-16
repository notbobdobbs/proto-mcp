package httpmcp

import (
	"fmt"
	"os/exec"
)

// OSNotify posts a macOS notification. The text must already be counts
// only. A missing osascript returns the error and does not print the
// text anywhere else.
func OSNotify(text string) error {
	script := fmt.Sprintf("display notification %q with title %q", text, "proto-mcp")
	return exec.Command("osascript", "-e", script).Run()
}
