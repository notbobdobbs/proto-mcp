package proton

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	gpa "github.com/ProtonMail/go-proton-api"
)

// hv9001JSON mirrors the real GET /core/v4/users 422 body captured while
// diagnosing this account's login — same field names, same "ownership-*"
// method names and WebUrl shape, sanitized token/URL values.
const hv9001JSON = `{
  "Status": 422,
  "Code": 9001,
  "Error": "Human verification required",
  "Details": {
    "HumanVerificationToken": "test-token-abc123",
    "HumanVerificationMethods": ["ownership-email", "ownership-sms"],
    "Direct": 1,
    "Description": "",
    "Title": "Verify account",
    "WebUrl": "https://verify.proton.me/?methods=ownership-email%2Cownership-sms&token=test-token-abc123",
    "ExpiresAt": 1789143997
  }
}`

func newHVAPIError(t *testing.T) *gpa.APIError {
	t.Helper()
	var err gpa.APIError
	if unmarshalErr := json.Unmarshal([]byte(hv9001JSON), &err); unmarshalErr != nil {
		t.Fatalf("unmarshal fixture: %v", unmarshalErr)
	}
	return &err
}

// TestTryWithHV_RetriesWithOriginalToken is the regression test for the
// bug this fixes: a prior version minted its own verification code via
// SendVerificationCode and retried with hv.Token replaced by that
// user-typed code. Proton rejected it with "Invalid or expired
// verification token" (Code 12087) because the token that comes back
// from the /users/code flow has nothing to do with the session the
// original 9001 error identified. The fix is to echo back the *exact*
// HumanVerificationToken/Methods from the original error, unmodified,
// after the user confirms they completed verification in the browser.
func TestTryWithHV_RetriesWithOriginalToken(t *testing.T) {
	hvErr := newHVAPIError(t)
	confirmCalls := 0
	creds := &Credentials{
		AskHVBrowserConfirm: func(_ context.Context, webURL string, again bool) error {
			confirmCalls++
			if again {
				t.Error("first confirmation should not be flagged again")
			}
			if webURL != "https://verify.proton.me/?methods=ownership-email%2Cownership-sms&token=test-token-abc123" {
				t.Errorf("unexpected webURL passed to confirm callback: %q", webURL)
			}
			return nil
		},
	}

	var gotRetryHV *gpa.APIHVDetails
	calls := 0
	result, err := tryWithHV(context.Background(), creds, func(hv *gpa.APIHVDetails) (string, error) {
		calls++
		if calls == 1 {
			if hv != nil {
				t.Errorf("first call should pass nil hv, got %+v", hv)
			}
			return "", hvErr
		}
		gotRetryHV = hv
		return "success", nil
	})
	if err != nil {
		t.Fatalf("tryWithHV returned error: %v", err)
	}
	if result != "success" {
		t.Errorf("result = %q, want %q", result, "success")
	}
	if calls != 2 {
		t.Fatalf("call count = %d, want 2", calls)
	}
	if confirmCalls != 1 {
		t.Errorf("AskHVBrowserConfirm called %d times, want 1", confirmCalls)
	}
	if gotRetryHV == nil {
		t.Fatal("retry call received nil hv")
	}
	if gotRetryHV.Token != "test-token-abc123" {
		t.Errorf("retry token = %q, want the original HumanVerificationToken unmodified", gotRetryHV.Token)
	}
	if len(gotRetryHV.Methods) != 2 || gotRetryHV.Methods[0] != "ownership-email" || gotRetryHV.Methods[1] != "ownership-sms" {
		t.Errorf("retry methods = %v, want the original HumanVerificationMethods unmodified", gotRetryHV.Methods)
	}
}

// TestTryWithHV_NoRetryOnSuccess ensures the common path (no 9001 at
// all) doesn't invoke the browser-confirm callback or retry.
func TestTryWithHV_NoRetryOnSuccess(t *testing.T) {
	creds := &Credentials{
		AskHVBrowserConfirm: func(context.Context, string, bool) error {
			t.Fatal("AskHVBrowserConfirm should not be called when the first call succeeds")
			return nil
		},
	}
	calls := 0
	result, err := tryWithHV(context.Background(), creds, func(*gpa.APIHVDetails) (int, error) {
		calls++
		return 42, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != 42 {
		t.Errorf("result = %d, want 42", result)
	}
	if calls != 1 {
		t.Errorf("call count = %d, want 1", calls)
	}
}

// TestTryWithHV_CaptchaOnlyWithoutWebURLRejected: a captcha offer with
// no usable verify.proton.me link fails closed. The guidance tells the
// user to sign in at mail.proton.me first and retry later, and the
// browser prompt is not shown — there is no page to open.
func TestTryWithHV_CaptchaOnlyWithoutWebURLRejected(t *testing.T) {
	captchaErr := &gpa.APIError{
		Status: 422,
		Code:   gpa.HumanVerificationRequired,
		Details: gpa.ErrDetails(`{
			"HumanVerificationToken": "tok",
			"HumanVerificationMethods": ["captcha"]
		}`),
	}
	creds := &Credentials{
		AskHVBrowserConfirm: func(context.Context, string, bool) error {
			t.Fatal("AskHVBrowserConfirm should not be called when captcha has no valid WebUrl")
			return nil
		},
	}
	_, err := tryWithHV(context.Background(), creds, func(*gpa.APIHVDetails) (int, error) {
		return 0, captchaErr
	})
	if err == nil {
		t.Fatal("expected an error for a captcha-only offer with no WebUrl, got nil")
	}
	if !strings.Contains(err.Error(), "mail.proton.me") || !strings.Contains(err.Error(), "retry later") {
		t.Errorf("err = %v, want guidance to sign in at mail.proton.me and retry later", err)
	}
}

// TestTryWithHV_CaptchaWithWebURLAccepted: Proton's CAPTCHA is completed
// on verify.proton.me in the user's browser. A captcha-only 9001 that
// carries a valid WebUrl is accepted, and the retry echoes the token
// and methods Proton issued.
func TestTryWithHV_CaptchaWithWebURLAccepted(t *testing.T) {
	const (
		token  = "captcha-token-issued"
		webURL = "https://verify.proton.me/?methods=captcha&token=captcha-token-issued"
	)
	captchaErr := captchaOffer(token, webURL)
	var shown string
	creds := &Credentials{
		AskHVBrowserConfirm: func(_ context.Context, got string, again bool) error {
			if again {
				t.Error("first confirmation should not be flagged again")
			}
			shown = got
			return nil
		},
	}
	var gotRetry *gpa.APIHVDetails
	calls := 0
	result, err := tryWithHV(context.Background(), creds, func(hv *gpa.APIHVDetails) (string, error) {
		calls++
		if calls == 1 {
			if hv != nil {
				t.Errorf("first call hv = %+v, want nil", hv)
			}
			return "", captchaErr
		}
		gotRetry = hv
		return "ok", nil
	})
	if err != nil || result != "ok" {
		t.Fatalf("tryWithHV = %q, %v; want ok", result, err)
	}
	if shown != webURL {
		t.Errorf("shown url = %q, want %q", shown, webURL)
	}
	if gotRetry == nil || gotRetry.Token != token {
		t.Fatalf("retry hv = %+v, want token %q unmodified", gotRetry, token)
	}
	if len(gotRetry.Methods) != 1 || gotRetry.Methods[0] != "captcha" {
		t.Errorf("retry methods = %v, want [captcha]", gotRetry.Methods)
	}
}

// TestTryWithHV_CaptchaHostileWebURLWithheld: a captcha offer whose
// WebUrl is not exactly https://verify.proton.me is not shown and not
// opened. The error carries the mail.proton.me guidance and none of the
// hostile text.
func TestTryWithHV_CaptchaHostileWebURLWithheld(t *testing.T) {
	hostile := []struct {
		name, webURL string
	}{
		{"other host", "https://evil.example/captcha"},
		{"escape sequence", "https://verify.proton.me/\x1b[2J"},
	}
	for _, tt := range hostile {
		t.Run(tt.name, func(t *testing.T) {
			webURL := tt.webURL
			creds := &Credentials{
				AskHVBrowserConfirm: func(context.Context, string, bool) error {
					t.Fatal("hostile WebUrl must not be shown")
					return nil
				},
			}
			_, err := tryWithHV(context.Background(), creds, func(*gpa.APIHVDetails) (int, error) {
				return 0, captchaOffer("tok", webURL)
			})
			if err == nil {
				t.Fatal("expected a refusal")
			}
			msg := err.Error()
			if strings.Contains(msg, "evil.example") || strings.Contains(msg, "\x1b") {
				t.Errorf("hostile WebUrl leaked into error: %q", msg)
			}
			if !strings.Contains(msg, "mail.proton.me") || !strings.Contains(msg, "retry later") {
				t.Errorf("err = %v, want mail.proton.me guidance", err)
			}
		})
	}
}

func captchaOffer(token, webURL string) *gpa.APIError {
	d, _ := json.Marshal(map[string]any{
		"HumanVerificationToken":   token,
		"HumanVerificationMethods": []string{"captcha"},
		"WebUrl":                   webURL,
	})
	return &gpa.APIError{Status: 422, Code: gpa.HumanVerificationRequired, Details: gpa.ErrDetails(d)}
}

// TestTryWithHV_NoPromptAvailable ensures a nil AskHVBrowserConfirm
// fails with a clear error (surfacing the WebUrl) rather than a nil
// pointer panic — relevant for any future non-interactive caller.
func TestTryWithHV_NoPromptAvailable(t *testing.T) {
	hvErr := newHVAPIError(t)
	creds := &Credentials{} // AskHVBrowserConfirm left nil
	_, err := tryWithHV(context.Background(), creds, func(*gpa.APIHVDetails) (int, error) {
		return 0, hvErr
	})
	if err == nil {
		t.Fatal("expected an error when no prompt callback is set")
	}
}

// TestTryWithHV_NonHVErrorPassesThrough ensures an unrelated API error
// (or any other error) is returned as-is, not swallowed or retried.
func TestTryWithHV_NonHVErrorPassesThrough(t *testing.T) {
	wantErr := errors.New("network exploded")
	creds := &Credentials{
		AskHVBrowserConfirm: func(context.Context, string, bool) error {
			t.Fatal("AskHVBrowserConfirm should not be called for a non-HV error")
			return nil
		},
	}
	calls := 0
	_, err := tryWithHV(context.Background(), creds, func(*gpa.APIHVDetails) (int, error) {
		calls++
		return 0, wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Errorf("err = %v, want %v", err, wantErr)
	}
	if calls != 1 {
		t.Errorf("call count = %d, want 1 (no retry on non-HV error)", calls)
	}
}

func TestHasOwnershipMethod(t *testing.T) {
	tests := []struct {
		methods []string
		want    bool
	}{
		{[]string{"ownership-email", "ownership-sms"}, true},
		{[]string{"ownership-email"}, true},
		{[]string{"captcha", "ownership-sms"}, true}, // captcha alongside a usable method
		{[]string{"captcha"}, false},
		{[]string{"captcha", "sms"}, false},         // bare "sms" isn't "ownership-sms"
		{[]string{"ownership-captcha"}, false},      // fails closed: not a visitable-URL flow
		{[]string{"ownership-email-future"}, false}, // unrecognised: fail closed, don't guess
		{nil, false},
	}
	for _, tt := range tests {
		if got := hasOwnershipMethod(tt.methods); got != tt.want {
			t.Errorf("hasOwnershipMethod(%v) = %v, want %v", tt.methods, got, tt.want)
		}
	}
}

// hvErrorWith builds a 9001 carrying the given token and WebUrl.
func hvErrorWith(token, webURL string) *gpa.APIError {
	d, _ := json.Marshal(map[string]any{
		"HumanVerificationToken":   token,
		"HumanVerificationMethods": []string{"ownership-email"},
		"WebUrl":                   webURL,
	})
	return &gpa.APIError{Status: 422, Code: gpa.HumanVerificationRequired, Details: gpa.ErrDetails(d)}
}

// Pressing Enter before the browser flow finishes produces a second
// 9001. That re-prompts (flagged again) instead of failing the whole
// login, and the retry echoes the token from the challenge whose link
// was just shown — the latest one, unmodified.
func TestTryWithHV_RepromptsOnRepeatChallenge(t *testing.T) {
	errs := []error{
		hvErrorWith("tok-1", "https://verify.proton.me/?token=tok-1"),
		hvErrorWith("tok-2", "https://verify.proton.me/?token=tok-2"),
	}
	var shown []string
	var againFlags []bool
	creds := &Credentials{
		AskHVBrowserConfirm: func(_ context.Context, webURL string, again bool) error {
			shown = append(shown, webURL)
			againFlags = append(againFlags, again)
			return nil
		},
	}
	var tokens []string
	calls := 0
	result, err := tryWithHV(context.Background(), creds, func(hv *gpa.APIHVDetails) (string, error) {
		calls++
		if hv != nil {
			tokens = append(tokens, hv.Token)
		}
		if calls <= len(errs) {
			return "", errs[calls-1]
		}
		return "ok", nil
	})
	if err != nil || result != "ok" {
		t.Fatalf("tryWithHV = %q, %v; want ok", result, err)
	}
	if strings.Join(tokens, ",") != "tok-1,tok-2" {
		t.Errorf("retry tokens = %v, want [tok-1 tok-2]", tokens)
	}
	if len(shown) != 2 || shown[1] != "https://verify.proton.me/?token=tok-2" {
		t.Errorf("links shown = %v", shown)
	}
	if len(againFlags) != 2 || againFlags[0] || !againFlags[1] {
		t.Errorf("again flags = %v, want [false true]", againFlags)
	}
}

func TestTryWithHV_GivesUpAfterMaxAttempts(t *testing.T) {
	prompts := 0
	creds := &Credentials{
		AskHVBrowserConfirm: func(context.Context, string, bool) error {
			prompts++
			return nil
		},
	}
	calls := 0
	_, err := tryWithHV(context.Background(), creds, func(*gpa.APIHVDetails) (int, error) {
		calls++
		return 0, newHVAPIError(t)
	})
	if err == nil || !strings.Contains(err.Error(), "still required") {
		t.Fatalf("err = %v, want a still-required error", err)
	}
	if prompts != maxHVAttempts || calls != maxHVAttempts+1 {
		t.Errorf("prompts = %d, calls = %d; want %d and %d", prompts, calls, maxHVAttempts, maxHVAttempts+1)
	}
}

func TestTryWithHV_ConfirmErrorStops(t *testing.T) {
	canceled := errors.New("canceled")
	creds := &Credentials{
		AskHVBrowserConfirm: func(context.Context, string, bool) error { return canceled },
	}
	calls := 0
	_, err := tryWithHV(context.Background(), creds, func(*gpa.APIHVDetails) (int, error) {
		calls++
		return 0, newHVAPIError(t)
	})
	if !errors.Is(err, canceled) || calls != 1 {
		t.Errorf("err = %v, calls = %d; want the confirm error and no retry", err, calls)
	}
}

// The link is written to the user's terminal as the thing to open, so
// only a clean https://verify.proton.me URL gets through.
func TestHVWebURL(t *testing.T) {
	ok := "https://verify.proton.me/?methods=ownership-email%2Cownership-sms&token=abc"
	tests := map[string]string{
		ok:                                   ok,
		"http://verify.proton.me/?token=abc": "",
		"https://verify.proton.me.evil.com/?t=abc": "",
		"https://evil.com/verify.proton.me":        "",
		"https://user@verify.proton.me/":           "",
		"https://verify.proton.me:8443/":           "",
		"https://verify.proton.me/\x1b[2J":         "", // ESC: terminal control sequence
		"https://verify.proton.me/\u202eevil":      "", // bidi override
		"https://verify.proton.me/ ok":             "", // space
		"":                                         "",
	}
	for in, want := range tests {
		details, _ := json.Marshal(map[string]string{"WebUrl": in})
		if got := hvWebURL(details); got != want {
			t.Errorf("hvWebURL(%q) = %q, want %q", in, got, want)
		}
	}
	if hvWebURL(nil) != "" || hvWebURL([]byte("not json")) != "" {
		t.Error("hvWebURL should return empty for missing/garbage details")
	}
}

func TestHVWebURLLengthCap(t *testing.T) {
	base := "https://verify.proton.me/"
	ok := base + strings.Repeat("a", maxHVWebURLLen-len(base))
	if len(ok) != maxHVWebURLLen {
		t.Fatalf("fixture length %d", len(ok))
	}
	long := ok + "b"
	for _, tt := range []struct {
		in, want string
	}{
		{ok, ok},
		{long, ""},
	} {
		details, err := json.Marshal(map[string]string{"WebUrl": tt.in})
		if err != nil {
			t.Fatal(err)
		}
		if got := hvWebURL(details); got != tt.want {
			t.Errorf("len %d: got len %d, want len %d", len(tt.in), len(got), len(tt.want))
		}
	}
}

func TestHVMethodErrorQuotesNames(t *testing.T) {
	err := hvMethodError([]string{"captcha\x1b[2J"}, errors.New("nope"))
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	if strings.Contains(msg, "\x1b") {
		t.Fatalf("raw escape leaked into error: %q", msg)
	}
	if !strings.Contains(msg, `"captcha\x1b[2J"`) {
		t.Fatalf("method name not quoted: %s", msg)
	}
}
