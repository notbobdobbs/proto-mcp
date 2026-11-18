package httpmcp

import (
	"fmt"
	"os/exec"
)

// OSNotify posts a macOS notification. The text is the short
// auth-failure notice: the count, the time window, the top reasons,
// the top client sources, and how to read the rest. It must not
// contain a token. A missing osascript returns the error and does
// not print the text anywhere else.
func OSNotify(text string) error {
	script := fmt.Sprintf("display notification %q with title %q", text, "proto-mcp")
	return exec.Command("osascript", "-e", script).Run()
}
