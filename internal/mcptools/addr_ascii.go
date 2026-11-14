package mcptools

import (
	"fmt"
	"strings"

	"golang.org/x/net/idna"

	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
)

// canonicalAddress returns the ASCII form of addr that is both shown
// and sent. The local part is an ASCII dot-atom. The domain is ASCII
// LDH, or an IDN reduced with UTS-46 (idna.Lookup) to punycode. Mapped
// or ignored characters — soft hyphen, CGJ, Hangul fillers, variation
// selectors, tag characters, ideographic and fullwidth dots — do not
// round-trip, so they are rejected instead of being rewritten into a
// different mailbox.
func canonicalAddress(addr string) (string, error) {
	if addr == "" || strings.ContainsAny(addr, " \t\r\n,;\"<>()[]") {
		return "", fmt.Errorf("recipient %q is not a plain address", addr)
	}
	if strings.Count(addr, "@") != 1 {
		return "", fmt.Errorf("recipient %q is not a plain address", addr)
	}
	local, domain, _ := strings.Cut(addr, "@")
	if !asciiLocal(local) {
		return "", fmt.Errorf("recipient %q has a local part that is not ASCII", addr)
	}
	asciiDomain, err := canonicalDomain(domain)
	if err != nil {
		return "", fmt.Errorf("recipient %q: %w", addr, err)
	}
	return local + "@" + asciiDomain, nil
}

func asciiLocal(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	if s[0] == '.' || s[len(s)-1] == '.' || strings.Contains(s, "..") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c > 127 || (c != '.' && !isAtext(c)) {
			return false
		}
	}
	return true
}

// isAtext is RFC 5322 atext, ASCII only.
func isAtext(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	switch c {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '/', '=', '?', '^', '_', '`', '{', '|', '}', '~':
		return true
	}
	return false
}

func canonicalDomain(domain string) (string, error) {
	if domain == "" || len(domain) > 253 {
		return "", fmt.Errorf("domain is empty or too long")
	}
	for _, r := range domain {
		if r < 0x20 || r == 0x7f || mcp.ContainsDisallowedPromptRune(string(r)) {
			return "", fmt.Errorf("domain contains a hidden or confusable character")
		}
	}
	ascii, err := idna.Lookup.ToASCII(domain)
	if err != nil {
		return "", fmt.Errorf("domain is not a valid IDN: %w", err)
	}
	uni, err := idna.Lookup.ToUnicode(ascii)
	if err != nil {
		return "", fmt.Errorf("domain is not a valid IDN: %w", err)
	}
	// Accept the original only when UTS-46 did not map or delete
	// anything. Punycode input equals ToASCII; a unicode IDN equals
	// ToUnicode. A soft hyphen or a lookalike dot becomes a different
	// string and is rejected.
	if domain != uni && !strings.EqualFold(domain, ascii) {
		return "", fmt.Errorf("domain contains a character UTS-46 would rewrite")
	}
	ascii = strings.ToLower(ascii)
	if !asciiDomainLabels(ascii) {
		return "", fmt.Errorf("domain is not an ASCII hostname")
	}
	return ascii, nil
}

func asciiDomainLabels(ascii string) bool {
	if ascii == "" || len(ascii) > 253 || strings.Contains(ascii, "..") {
		return false
	}
	labels := strings.Split(ascii, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if c > 127 || !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	// The last label is not all digits (rejects a bare IPv4 lookalike
	// that skipped the dots). Real IDNA TLDs have a letter.
	last := labels[len(labels)-1]
	allDigit := true
	for i := 0; i < len(last); i++ {
		if last[i] < '0' || last[i] > '9' {
			allDigit = false
			break
		}
	}
	return !allDigit
}

// rejectHiddenText refuses subject and attachment names that contain
// bidi controls or invisible/confusable characters. The dialog
// sanitizer would drop them, so sending the original would hide the
// character from the person approving.
func rejectHiddenText(kind, s string) error {
	if mcp.ContainsDisallowedPromptRune(s) {
		return fmt.Errorf("%s contains a hidden or bidirectional character and was not sent", kind)
	}
	return nil
}
