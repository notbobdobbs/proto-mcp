package mcptools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestSanitizeField_CollapsesLineBreaks(t *testing.T) {
	got := sanitizeField("real@y.com\nBCC: evil@x.com\r\tx To: a To: b\u0085To: c")
	if strings.ContainsAny(got, "\r\n\t  \u0085") {
		t.Errorf("sanitizeField left a line break / tab in %q", got)
	}
}

// A recipient value carrying an embedded newline must not become a
// second dialog line, and it must not be rewritten into a different
// address that is then sent. Issue #125 refuses the call: the address
// cannot be shown exactly as it would be delivered.
func TestSendPromptBody_NoNewlineInjection(t *testing.T) {
	snap := sendPromptSnapshot(Deps{}, "mail_send")
	_, body, _, err := snap(context.Background(), json.RawMessage(`{"to":["real@y.com\nBCC: evil@x.com"],"subject":"hi"}`))
	if err == nil {
		t.Fatalf("newline in a recipient was shown instead of refused:\n%s", body)
	}
}
