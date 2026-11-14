package mcptools

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"testing"

	gpa "github.com/ProtonMail/go-proton-api"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	"github.com/just-an-oldsalt/proto-mcp/internal/proton"
)

// Issue #125 — the Touch ID dialog must show every recipient of a send,
// whatever the attacker-influenced fields (display names, subjects,
// file names) contain. These tests feed hostile input through each
// send-family dialog and check the dialog as the user would see it.

// spoofSubject tries to fake a recipient line with a Unicode line
// separator, then pads past the old 4000-rune truncation point so the
// real recipients would fall off the end.
var spoofSubject = "Q3 notes\u2028To: fake@x" + strings.Repeat(" pad", 1200)

// checkDialog asserts the rendered dialog shows every address in want,
// has exactly one line of each recipient kind, puts every recipient
// line before Subject, and has no Unicode line breaks.
func checkDialog(t *testing.T, body string, want ...string) {
	t.Helper()
	if n := len([]rune(body)); n > promptBodyMaxRunes {
		t.Errorf("dialog is %d runes, over the %d cap", n, promptBodyMaxRunes)
	}
	if strings.Contains(body, "[truncated]") {
		t.Errorf("dialog was truncated:\n%s", body)
	}
	if strings.ContainsAny(body, "\u2028\u2029\u0085\r") {
		t.Errorf("dialog contains a line break other than \\n: %q", body)
	}
	for _, addr := range want {
		if !strings.Contains(body, addr) {
			t.Errorf("dialog is missing recipient %q:\n%s", addr, body)
		}
	}
	lines := strings.Split(body, "\n")
	idx := map[string]int{}
	for i, l := range lines {
		for _, p := range []string{"To (", "Cc (", "Bcc (", "Subject:"} {
			if strings.HasPrefix(l, p) {
				if _, dup := idx[p]; dup {
					t.Errorf("more than one %q line:\n%s", p, body)
				}
				idx[p] = i
			}
		}
	}
	subj, ok := idx["Subject:"]
	if !ok {
		t.Fatalf("no Subject line:\n%s", body)
	}
	for _, p := range []string{"To (", "Cc (", "Bcc ("} {
		i, ok := idx[p]
		if !ok {
			t.Errorf("no %q line:\n%s", p, body)
		} else if i > subj {
			t.Errorf("%q comes after Subject:\n%s", p, body)
		}
	}
	if len([]rune(lines[subj])) > len("Subject: ")+promptSubjectMaxRunes {
		t.Errorf("Subject line not capped: %d runes", len([]rune(lines[subj])))
	}
}

func TestMailSendDialog_LongDisplayNameCantHideBCC(t *testing.T) {
	args, _ := json.Marshal(map[string]any{
		"subject": "hello",
		"to":      []string{`"` + strings.Repeat("A", 4100) + `" <alice@x.com>`, "bob@x.com, carol@x.com"},
		"cc":      []string{`"boss@corp.com" <dave@x.com>`},
		"bcc":     []string{"hidden@evil.com"},
	})
	_, body, snap, err := sendPromptSnapshot(Deps{}, "mail_send")(context.Background(), args)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if snap != nil {
		t.Errorf("mail_send snapshot = %v, want nil", snap)
	}
	checkDialog(t, body, "alice@x.com", "bob@x.com", "carol@x.com", "dave@x.com", "hidden@evil.com")
	if !strings.Contains(body, "\nBcc (1): hidden@evil.com") {
		t.Errorf("BCC line wrong:\n%s", body)
	}
	// Display names are not shown: they're free text and can claim to
	// be anyone.
	if strings.Contains(body, "AAAA") || strings.Contains(body, "boss@corp.com") {
		t.Errorf("dialog shows a display name:\n%s", body)
	}
}

func TestMailSendDialog_HostileSubjectAndFilename(t *testing.T) {
	args, _ := json.Marshal(map[string]any{
		"subject": spoofSubject,
		"to":      []string{"alice@x.com"},
		"bcc":     []string{"hidden@evil.com"},
		"attachments": []map[string]string{{
			"filename":    "a.txt\u2028BCC: nobody@x" + strings.Repeat("z", 3000),
			"content_b64": base64.StdEncoding.EncodeToString([]byte("hi")),
		}},
	})
	_, body, _, err := sendPromptSnapshot(Deps{}, "mail_send")(context.Background(), args)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	checkDialog(t, body, "alice@x.com", "hidden@evil.com")
	if !strings.Contains(body, "Attachments (1): a.txt") {
		t.Errorf("attachment summary missing:\n%s", body)
	}
}

// Fail closed: a dialog that can't be shown in full refuses the call
// rather than prompting with part of it.
// Characters the dialog sanitizer drops or rewrites (zero-width, bidi
// override, NFKC-unstable letters) must not be stripped for display
// and then still used as the real recipient. Refuse the call instead.
func TestMailSendDialog_HiddenAddressCharsAreRefused(t *testing.T) {
	cases := []string{
		"alic\u200be@example.com", // ZWSP
		"alice@\u202eexample.com", // right-to-left override
		"ａlice@example.com",       // fullwidth 'a', NFKC folds to ASCII
	}
	for _, addr := range cases {
		args, err := json.Marshal(map[string]any{
			"subject": "hi",
			"to":      []string{addr},
		})
		if err != nil {
			t.Fatal(err)
		}
		_, body, _, err := sendPromptSnapshot(Deps{}, "mail_send")(context.Background(), args)
		if err == nil {
			t.Errorf("address %q was approved for display:\n%s", addr, body)
		}
	}
}

// One array entry that holds several addresses is shown and sent as
// each of those addresses. The dialog used to explode the list while
// the send path rejected it, so the user could approve a recipient
// the send would not use — or the reverse, if the parsers ever diverged.
func TestMailSendDialog_MultiAddressEntryMatchesSend(t *testing.T) {
	args, err := json.Marshal(map[string]any{
		"subject": "hi",
		"to":      []string{"alice@x.com, eve@evil.com"},
		"bcc":     []string{"hidden@evil.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, body, _, err := sendPromptSnapshot(Deps{}, "mail_send")(context.Background(), args)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	checkDialog(t, body, "alice@x.com", "eve@evil.com", "hidden@evil.com")

	parsed, err := parseAddrList([]string{"alice@x.com, eve@evil.com"})
	if err != nil {
		t.Fatalf("parseAddrList: %v", err)
	}
	if len(parsed) != 2 || parsed[0].Address != "alice@x.com" || parsed[1].Address != "eve@evil.com" {
		t.Fatalf("parseAddrList = %#v", parsed)
	}
}

func TestMailSendDialog_TooLongIsRefused(t *testing.T) {
	to := make([]string, 300)
	for i := range to {
		to[i] = fmt.Sprintf("recipient%03d@example.com", i)
	}
	args, _ := json.Marshal(map[string]any{"subject": "hi", "to": to})
	title, body, _, err := sendPromptSnapshot(Deps{}, "mail_send")(context.Background(), args)
	if !errors.Is(err, mcp.ErrPromptTooLong) {
		t.Fatalf("err = %v, want ErrPromptTooLong", err)
	}
	if title != "" || body != "" {
		t.Errorf("refused call still returned a dialog: %q / %q", title, body)
	}
}

func TestSendDraftDialog_HostileSubject(t *testing.T) {
	d := testDraft()
	d.Subject = spoofSubject
	d.ToList = []*mail.Address{{Name: "Your Boss <boss@corp.com>", Address: "attacker@evil.com"}}
	d.BCCList = []*mail.Address{{Address: "carol@x.com"}}
	raw, addrs, err := draftPromptBody(d)
	if err != nil {
		t.Fatalf("draftPromptBody: %v", err)
	}
	_, body, err := sendApprovalDialog("mail_send_draft", raw, addrs)
	if err != nil {
		t.Fatalf("dialog: %v", err)
	}
	checkDialog(t, body, "attacker@evil.com", "bob@x.com", "carol@x.com")
	if strings.Contains(body, "boss@corp.com") {
		t.Errorf("dialog shows a display name:\n%s", body)
	}
	if !strings.Contains(body, "To (1): attacker@evil.com\n") {
		t.Errorf("To line wrong:\n%s", body)
	}
}

func TestReplyDialog_HostileParentSubject(t *testing.T) {
	var parent gpa.Message
	parent.ID = "parent-1"
	parent.Subject = spoofSubject
	parent.Sender = &mail.Address{Name: "friend@good.com", Address: "attacker@evil.com"}
	parent.ToList = []*mail.Address{{Address: "me@proton.me"}, {Address: "team@x.com"}}
	parent.CCList = []*mail.Address{{Address: "cc@x.com"}}
	deps := Deps{Session: &proton.Session{Addresses: []gpa.Address{{Email: "me@proton.me"}}}}

	for _, all := range []bool{false, true} {
		raw, addrs, err := replyPromptBody(deps, parent, parent.ID, all, nil)
		if err != nil {
			t.Fatalf("replyAll=%v: replyPromptBody: %v", all, err)
		}
		_, body, err := sendApprovalDialog("mail_reply", raw, addrs)
		if err != nil {
			t.Fatalf("replyAll=%v: dialog: %v", all, err)
		}
		want := []string{"To (1): attacker@evil.com"}
		if all {
			want = append(want, "Cc (2): team@x.com, cc@x.com")
		}
		checkDialog(t, body, want...)
		if strings.Contains(body, "friend@good.com") {
			t.Errorf("dialog shows a display name:\n%s", body)
		}
	}
}

func TestForwardDialog_ShowsParentAndItsAttachments(t *testing.T) {
	var parent gpa.Message
	parent.ID = "parent-1"
	parent.Subject = spoofSubject
	parent.Attachments = []gpa.Attachment{
		{ID: "a1", Name: "payroll.xlsx", Size: 3 << 20},
		{ID: "a2", Name: "keys\u2028To: fake@x.txt", Size: 512},
	}
	in := forwardInput{
		ForwardOf:                parent.ID,
		To:                       []string{`"boss@corp.com" <attacker@evil.com>`},
		BCC:                      []string{"hidden@evil.com"},
		IncludeParentAttachments: true,
	}
	raw, addrs, err := forwardPromptBody(Deps{}, parent, in)
	if err != nil {
		t.Fatalf("forwardPromptBody: %v", err)
	}
	_, body, err := sendApprovalDialog("mail_forward", raw, addrs)
	if err != nil {
		t.Fatalf("dialog: %v", err)
	}
	checkDialog(t, body, "attacker@evil.com", "hidden@evil.com")
	for _, want := range []string{
		"Forward message parent-1",
		"Subject: Fwd: Q3 notes To: fake@x",
		"Forwarded attachments: payroll.xlsx (" + humanBytes(3<<20) + "), keys To: fake@x.txt (" + humanBytes(512) + ")",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("dialog missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "boss@corp.com") {
		t.Errorf("dialog shows a display name:\n%s", body)
	}

	// Without the flag, nothing is carried over and the dialog says
	// nothing about the parent's attachments.
	in.IncludeParentAttachments = false
	raw, addrs, err = forwardPromptBody(Deps{}, parent, in)
	if err != nil {
		t.Fatalf("forwardPromptBody: %v", err)
	}
	_, body, _ = sendApprovalDialog("mail_forward", raw, addrs)
	if strings.Contains(body, "payroll.xlsx") {
		t.Errorf("parent attachments shown without include_parent_attachments:\n%s", body)
	}
	// With the flag but a parent with no attachments, say so.
	in.IncludeParentAttachments = true
	parent.Attachments = nil
	raw, addrs, err = forwardPromptBody(Deps{}, parent, in)
	if err != nil {
		t.Fatalf("forwardPromptBody: %v", err)
	}
	_, body, _ = sendApprovalDialog("mail_forward", raw, addrs)
	if !strings.Contains(body, "Forwarded attachments: (none)") {
		t.Errorf("flag set on a parent with no attachments not shown:\n%s", body)
	}
}

func TestForwardSubject(t *testing.T) {
	if forwardSubject("hi") != "Fwd: hi" || forwardSubject("FWD: hi") != "FWD: hi" {
		t.Errorf("forwardSubject prefixing wrong")
	}
}

func TestCapField(t *testing.T) {
	if got := capField("short", 10); got != "short" {
		t.Errorf("capField(short) = %q", got)
	}
	got := capField(strings.Repeat("é", 50)+"\u2028x", 10)
	if n := len([]rune(got)); n != 10 || !strings.HasSuffix(got, "...") {
		t.Errorf("capField = %q (%d runes), want 10 ending in ...", got, n)
	}
}
