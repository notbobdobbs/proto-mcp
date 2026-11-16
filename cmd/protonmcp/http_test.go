package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/httpconfig"
	"github.com/just-an-oldsalt/proto-mcp/internal/keystore"
	"github.com/just-an-oldsalt/proto-mcp/internal/mcperrors"
	"github.com/just-an-oldsalt/proto-mcp/internal/secret"
)

type memVault struct {
	tok secret.Secret
	has bool
}

func (m *memVault) Load() (secret.Secret, error) {
	if !m.has {
		return secret.Secret{}, keystore.ErrHTTPTokenNotFound
	}
	return m.tok.Clone(), nil
}

func (m *memVault) Save(s secret.Secret) error {
	if m.has {
		m.tok.Zero()
	}
	m.tok = s.Clone()
	m.has = true
	return nil
}

func (m *memVault) Delete() error {
	m.tok.Zero()
	m.has = false
	return nil
}

type fakeBoard struct {
	value string
}

func (f *fakeBoard) Read() (string, error) { return f.value, nil }
func (f *fakeBoard) Write(s string) error  { f.value = s; return nil }
func (f *fakeBoard) Clear() error          { f.value = ""; return nil }

func testDeps(t *testing.T) (httpDeps, *memVault, *fakeBoard, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	vault := &memVault{}
	board := &fakeBoard{}
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	return httpDeps{
		vault:      vault,
		board:      board,
		screenLock: func() bool { return true },
		signal:     func() error { return nil },
		configPath: filepath.Join(t.TempDir(), "http.yaml"),
		stdout:     stdout,
		stderr:     stderr,
		approve:    func(context.Context) error { return nil },
		after:      func(time.Duration, func()) {},
	}, vault, board, stdout, stderr
}

func TestHTTPEnableWarnsWhenScreenLockIsOffAndStillEnables(t *testing.T) {
	deps, vault, _, stdout, stderr := testDeps(t)
	tok, err := keystore.GenerateHTTPToken()
	if err != nil {
		t.Fatal(err)
	}
	defer tok.Zero()
	if err := vault.Save(tok); err != nil {
		t.Fatal(err)
	}
	var signaled int
	deps.signal = func() error { signaled++; return nil }
	deps.screenLock = func() bool { return false }

	if err := runHTTPWith(context.Background(), []string{"enable"}, deps); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "screen lock is off") {
		t.Fatalf("stderr = %q, want the screen-lock warning", stderr.String())
	}
	cfg, err := httpconfig.Load(deps.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Enabled {
		t.Fatal("enable with screen lock off did not write enabled: true")
	}
	if signaled != 1 {
		t.Fatalf("signal calls = %d, want 1", signaled)
	}
	if strings.Contains(stdout.String()+stderr.String(), mustHex(t, tok)) {
		t.Fatal("enable printed the token")
	}
	info, err := os.Stat(deps.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("http.yaml mode = %o, want 0600", info.Mode().Perm())
	}
}

func TestHTTPEnableScreenLockOnIsSilent(t *testing.T) {
	deps, vault, _, _, stderr := testDeps(t)
	tok, err := keystore.GenerateHTTPToken()
	if err != nil {
		t.Fatal(err)
	}
	defer tok.Zero()
	_ = vault.Save(tok)
	deps.screenLock = func() bool { return true }
	if err := runHTTPWith(context.Background(), []string{"enable"}, deps); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stderr.String(), "screen lock is off") {
		t.Fatalf("warning printed while screen lock is on: %s", stderr.String())
	}
}

func TestHTTPEnableRefusesWithoutToken(t *testing.T) {
	deps, _, _, _, _ := testDeps(t)
	err := runHTTPWith(context.Background(), []string{"enable"}, deps)
	if err == nil {
		t.Fatal("enable without a token succeeded")
	}
	if _, statErr := os.Stat(deps.configPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("enable wrote a file without a token: %v", statErr)
	}
}

func TestHTTPEnableKeepsABadFileOff(t *testing.T) {
	deps, vault, _, _, _ := testDeps(t)
	tok, err := keystore.GenerateHTTPToken()
	if err != nil {
		t.Fatal(err)
	}
	defer tok.Zero()
	_ = vault.Save(tok)
	if err := os.WriteFile(deps.configPath, []byte("enabled: true\nremote_tools: ['*']\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var signaled int
	deps.signal = func() error { signaled++; return nil }
	if err := runHTTPWith(context.Background(), []string{"enable"}, deps); err == nil {
		t.Fatal("enable applied a bad file")
	}
	data, _ := os.ReadFile(deps.configPath)
	if !strings.Contains(string(data), "*") {
		t.Fatalf("bad file was rewritten: %s", data)
	}
	if signaled != 0 {
		t.Fatal("bad file signaled the daemon")
	}
}

func TestHTTPRotateReplacesTokenAndClearsClipboard(t *testing.T) {
	deps, vault, board, stdout, stderr := testDeps(t)
	var waits []time.Duration
	var clears []func()
	deps.after = func(d time.Duration, fn func()) {
		waits = append(waits, d)
		clears = append(clears, fn)
	}
	if err := runHTTPWith(context.Background(), []string{"token", "rotate"}, deps); err != nil {
		t.Fatal(err)
	}
	first, err := vault.Load()
	if err != nil {
		t.Fatal(err)
	}
	defer first.Zero()
	firstHex := mustHex(t, first)
	if board.value != firstHex {
		t.Fatalf("clipboard = %q, want the token", board.value)
	}
	if strings.Contains(stdout.String()+stderr.String(), firstHex) {
		t.Fatal("rotate wrote the token to output")
	}
	if len(waits) != 1 || waits[0] != 60*time.Second {
		t.Fatalf("clear scheduled at %v, want 60s", waits)
	}

	if err := runHTTPWith(context.Background(), []string{"token", "rotate"}, deps); err != nil {
		t.Fatal(err)
	}
	second, err := vault.Load()
	if err != nil {
		t.Fatal(err)
	}
	defer second.Zero()
	if keystore.HTTPTokenEqual(first.Bytes(), second.Bytes()) {
		t.Fatal("rotate did not replace the token")
	}
	if keystore.HTTPTokenMatches(second.Bytes(), firstHex) {
		t.Fatal("old token still matches")
	}
	if !keystore.HTTPTokenMatches(second.Bytes(), board.value) {
		t.Fatal("clipboard does not hold the new token")
	}
	secondHex := board.value
	clears[1]()
	if board.value != "" {
		t.Fatalf("clipboard still holds the token after the timer: %q", board.value)
	}
	board.value = "something the user copied later"
	clears[1]()
	if board.value != "something the user copied later" {
		t.Fatalf("clear wiped a newer clipboard value: %q", board.value)
	}
	if strings.Contains(stdout.String()+stderr.String(), secondHex) || strings.Contains(stdout.String(), firstHex) {
		t.Fatal("output contains a token")
	}
}

func TestHTTPRotateRejectsAnArgument(t *testing.T) {
	deps, vault, board, stdout, _ := testDeps(t)
	err := runHTTPWith(context.Background(), []string{"token", "rotate", "not-a-real-token"}, deps)
	if err == nil {
		t.Fatal("rotate accepted an argument")
	}
	if vault.has {
		t.Fatal("rotate with an argument stored a token")
	}
	if board.value != "" || stdout.Len() != 0 {
		t.Fatalf("rotate with an argument wrote output or clipboard: %q %q", stdout.String(), board.value)
	}
}

func TestHTTPShowDeclineCopiesNothing(t *testing.T) {
	deps, vault, board, stdout, stderr := testDeps(t)
	tok, err := keystore.GenerateHTTPToken()
	if err != nil {
		t.Fatal(err)
	}
	defer tok.Zero()
	_ = vault.Save(tok)
	board.value = "leave-this"
	deps.approve = func(context.Context) error {
		return errors.New("declined")
	}
	if err := runHTTPWith(context.Background(), []string{"token", "show"}, deps); err == nil {
		t.Fatal("declined show succeeded")
	}
	if board.value != "leave-this" {
		t.Fatalf("clipboard changed on decline: %q", board.value)
	}
	if strings.Contains(stdout.String()+stderr.String(), mustHex(t, tok)) {
		t.Fatal("declined show printed the token")
	}
}

func TestHTTPShowCopiesWithoutPrinting(t *testing.T) {
	deps, vault, board, stdout, stderr := testDeps(t)
	tok, err := keystore.GenerateHTTPToken()
	if err != nil {
		t.Fatal(err)
	}
	defer tok.Zero()
	_ = vault.Save(tok)
	if err := runHTTPWith(context.Background(), []string{"token", "show"}, deps); err != nil {
		t.Fatal(err)
	}
	if board.value != mustHex(t, tok) {
		t.Fatalf("clipboard = %q", board.value)
	}
	if strings.Contains(stdout.String()+stderr.String(), board.value) {
		t.Fatal("show printed the token")
	}
}

func TestHTTPRevokeDropsTheToken(t *testing.T) {
	deps, vault, _, stdout, stderr := testDeps(t)
	tok, err := keystore.GenerateHTTPToken()
	if err != nil {
		t.Fatal(err)
	}
	defer tok.Zero()
	_ = vault.Save(tok)
	hexText := mustHex(t, tok)
	if err := runHTTPWith(context.Background(), []string{"token", "revoke"}, deps); err != nil {
		t.Fatal(err)
	}
	if vault.has {
		t.Fatal("token still stored")
	}
	if _, err := vault.Load(); !errors.Is(err, keystore.ErrHTTPTokenNotFound) {
		t.Fatalf("load after revoke = %v", err)
	}
	if strings.Contains(stdout.String()+stderr.String(), hexText) {
		t.Fatal("revoke printed the token")
	}
	// The item is gone, so a later check cannot match the old token.
	// The HTTP door maps that to 401. There is no listener in this change.
	if got, err := vault.Load(); err == nil && keystore.HTTPTokenMatches(got.Bytes(), hexText) {
		got.Zero()
		t.Fatal("revoked token still authorizes")
	}
}

func TestHTTPStatusDoesNotPrintTheToken(t *testing.T) {
	deps, vault, _, stdout, stderr := testDeps(t)
	tok, err := keystore.GenerateHTTPToken()
	if err != nil {
		t.Fatal(err)
	}
	defer tok.Zero()
	_ = vault.Save(tok)
	if err := runHTTPWith(context.Background(), []string{"status"}, deps); err != nil {
		t.Fatal(err)
	}
	out := stdout.String()
	if !strings.Contains(out, "token: present") || !strings.Contains(out, "enabled: false") || !strings.Contains(out, "sessions: 0") {
		t.Fatalf("status = %q", out)
	}
	if strings.Contains(out+stderr.String(), mustHex(t, tok)) {
		t.Fatal("status printed the token")
	}
}

func TestHTTPShowAndRotateOnNonDarwinPrintNothing(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("this is the non-macOS refusal")
	}
	for _, args := range [][]string{{"token", "show"}, {"token", "rotate"}} {
		stdout := &bytes.Buffer{}
		stderr := &bytes.Buffer{}
		deps := httpDeps{stdout: stdout, stderr: stderr, signal: func() error { return nil }}
		err := runHTTPWith(context.Background(), args, deps)
		if err == nil {
			t.Fatalf("%v succeeded on non-macOS", args)
		}
		if stdout.Len() != 0 || stderr.Len() != 0 {
			t.Fatalf("%v wrote output: stdout=%q stderr=%q", args, stdout.String(), stderr.String())
		}
	}
}

func TestTokenShowHelperExitCodes(t *testing.T) {
	ctx := context.Background()
	decline := helperScript(t, "#!/bin/sh\nexit 1\n")
	err := runTokenShowHelper(ctx, decline)
	if !errors.Is(err, mcperrors.ErrUserCanceled) {
		t.Fatalf("exit 1 = %v, want ErrUserCanceled", err)
	}

	out := filepath.Join(t.TempDir(), "payload.json")
	ok := helperScript(t, "#!/bin/sh\ncat > '"+out+"'\nexit 0\n")
	if err := runTokenShowHelper(ctx, ok); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, `"confirm":true`) {
		t.Fatalf("helper payload dropped confirm: %s", text)
	}
	if !strings.Contains(text, "does not approve sending mail") {
		t.Fatalf("helper payload does not say this is not a send: %s", text)
	}
}

func TestDoctorScreenLockWarningDoesNotFail(t *testing.T) {
	prev := screenLockOn
	t.Cleanup(func() { screenLockOn = prev })

	screenLockOn = func() bool { return false }
	var off report
	checkScreenLock(&off)
	if off.worst() != stateWarn {
		t.Fatalf("off state = %v, want warn", off.worst())
	}
	if off.worst() == stateFail {
		t.Fatal("screen lock off fails doctor")
	}
	if !strings.Contains(off.checks[0].detail, "screen lock is off") {
		t.Fatalf("detail = %q", off.checks[0].detail)
	}

	screenLockOn = func() bool { return true }
	var on report
	checkScreenLock(&on)
	if strings.Contains(on.checks[0].detail, "screen lock is off") {
		t.Fatalf("screen lock on still warns: %q", on.checks[0].detail)
	}
	if on.worst() != stateOK {
		t.Fatalf("on state = %v, want ok", on.worst())
	}
}

func helperScript(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fake-touchid")
	if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func mustHex(t *testing.T, s secret.Secret) string {
	t.Helper()
	text, err := keystore.EncodeHTTPToken(s.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return text
}
