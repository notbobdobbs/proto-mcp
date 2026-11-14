package mcptools

import (
	"context"
	"encoding/json"
	"net/mail"
	"strings"
	"testing"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
)

func TestRecipientAllowlistRejectsConfusables(t *testing.T) {
	cases := []string{
		"alic\u00ad@example.com",  // soft hyphen
		"ali\u034fce@example.com", // CGJ
		"a\u115f@example.com",     // Hangul filler
		"a\u1160@example.com",
		"a\u3164@example.com",
		"a\uffa0@example.com",
		"alice@evil\u3002com",         // ideographic full stop
		"alice@evil\uff0ecom",         // fullwidth full stop
		"alice@evil\uff61com",         // halfwidth ideographic full stop
		"alice@exam\ufe0fple.com",     // variation selector
		"alice@example.com\U000E0100", // variation selector supplement
		"alice@example.com\U000E0001", // tag character
		"alice@\u202eexample.com",     // RLO
	}
	for _, addr := range cases {
		if _, err := canonicalAddress(addr); err == nil {
			t.Errorf("canonicalAddress(%q) succeeded", addr)
		}
		args, err := json.Marshal(map[string]any{"to": []string{addr}, "subject": "hi"})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := sendPromptSnapshot(Deps{}, "mail_send")(context.Background(), args); err == nil {
			t.Errorf("dialog accepted %q", addr)
		}
	}
}

func TestRecipientAllowlistKeepsIDNAsPunycode(t *testing.T) {
	got, err := canonicalAddress("user@münchen.de")
	if err != nil {
		t.Fatal(err)
	}
	if got != "user@xn--mnchen-3ya.de" {
		t.Fatalf("canonical = %q", got)
	}
	plain, err := canonicalAddress("Alice@Example.COM")
	if err != nil {
		t.Fatal(err)
	}
	if plain != "Alice@example.com" {
		t.Fatalf("ascii canonical = %q", plain)
	}
}

func TestSubjectBidiIsRejectedNotRewritten(t *testing.T) {
	subject := "hello\u202eworld"
	args, err := json.Marshal(map[string]any{
		"to":      []string{"alice@example.com"},
		"subject": subject,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, body, _, err := sendPromptSnapshot(Deps{}, "mail_send")(context.Background(), args)
	if err == nil {
		t.Fatalf("subject with RLO was shown as %q", body)
	}
	if !mcp.ContainsDisallowedPromptRune(subject) {
		t.Fatal("RLO was not classified as disallowed")
	}
	// The sent subject is the caller's string. buildDraftTemplate
	// refuses it instead of storing a stripped copy.
	if _, _, err := buildDraftTemplate(Deps{}, subject, []string{"alice@example.com"}, nil, nil, "body", ""); err == nil {
		t.Fatal("buildDraftTemplate accepted an RLO subject")
	}
}

func TestAttachmentNameBidiIsStrippedBeforeSend(t *testing.T) {
	// Outbound filenames are sanitized before upload, so the bytes
	// that are sent do not contain the RLO the dialog would hide.
	// The summary is built from that same sanitized name.
	got, err := decodeAndValidateAttachments(Deps{}, []sendAttachmentInput{{
		Filename:   "report\u202e.txt.exe",
		ContentB64: "aGk=",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(got[0].Filename, 0x202e) {
		t.Fatalf("sent filename still contains RLO: %q", got[0].Filename)
	}
	summary, err := attachmentsSummary(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(summary, 0x202e) || !strings.Contains(summary, got[0].Filename) {
		t.Fatalf("summary %q does not show the sent name %q", summary, got[0].Filename)
	}
}

func TestEmptyCcAndBccCountZero(t *testing.T) {
	lines := recipientLines("alice@example.com", "", "")
	body := strings.Join(lines, "\n")
	if !strings.Contains(body, "Cc (0): (none)") || !strings.Contains(body, "Bcc (0): (none)") {
		t.Fatalf("empty lists counted as present:\n%s", body)
	}
	if !strings.Contains(body, "To (1): alice@example.com") {
		t.Fatalf("to count wrong:\n%s", body)
	}
}

func TestIDNRecipientMatchesApprovalAndSend(t *testing.T) {
	line, canon, err := joinAddrs([]string{"user@münchen.de"})
	if err != nil {
		t.Fatal(err)
	}
	if line != "user@xn--mnchen-3ya.de" || len(canon) != 1 || canon[0] != line {
		t.Fatalf("dialog line = %q canon = %v", line, canon)
	}
	// The send gate uses the same function and accepts the punycode
	// the dialog showed. It must not reject that string later.
	got, err := canonicalRecipientEntries([]string{"user@münchen.de"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != canon[0] || !addressShownAsSent(got[0]) {
		t.Fatalf("send canonical = %v, dialog = %v", got, canon)
	}
	// A reply recipient is canonicalized in the dialog instead of
	// failing closed with a generic join error.
	replyLine, replyCanon, err := joinAddrs([]string{"user@münchen.de"})
	if err != nil || replyLine != got[0] || replyCanon[0] != got[0] {
		t.Fatalf("reply dialog = %q %v err=%v", replyLine, replyCanon, err)
	}
}

func TestSubjectFormatCharIsRefusedNotRewritten(t *testing.T) {
	subject := "hello\u2028world"
	if _, err := exactField("subject", subject); err == nil {
		t.Fatal("line separator was accepted")
	}
	args, err := json.Marshal(map[string]any{
		"to":      []string{"alice@example.com"},
		"subject": subject,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, body, _, err := sendPromptSnapshot(Deps{}, "mail_send")(context.Background(), args); err == nil {
		t.Fatalf("rewritten subject was shown:\n%s", body)
	}
	clean := "hello world"
	shown, err := exactField("subject", clean)
	if err != nil || shown != clean {
		t.Fatalf("clean subject = %q %v", shown, err)
	}
}

func TestPickAddrListDoesNotClearOnReject(t *testing.T) {
	fallback := []*mail.Address{{Address: "keep@example.com"}}
	input := "alic\u200be@example.com"
	got, err := pickAddrList([]string{input}, fallback)
	if err == nil {
		t.Fatal("expected the rejected recipient to be an error")
	}
	if got != nil {
		t.Fatalf("rejected list replaced the field: %#v", got)
	}
	if !strings.Contains(err.Error(), "example.com") {
		t.Fatalf("error %q dropped the user's input", err)
	}
	kept, err := pickAddrList(nil, fallback)
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != 1 || kept[0].Address != "keep@example.com" {
		t.Fatalf("empty update did not keep the draft field: %#v", kept)
	}
}
