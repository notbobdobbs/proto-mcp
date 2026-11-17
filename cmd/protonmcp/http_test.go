package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
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
	mu    sync.Mutex
	value string
}

func (f *fakeBoard) Read() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.value, nil
}
func (f *fakeBoard) Write(s string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.value = s
	return nil
}
func (f *fakeBoard) Clear() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.value = ""
	return nil
}

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
		hold:       200 * time.Millisecond,
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

func TestHTTPDisableRewritesUnparseableFile(t *testing.T) {
	deps, _, _, stdout, _ := testDeps(t)
	if err := os.WriteFile(deps.configPath, []byte("enabled: true\nremote_tools: [*\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var signaled int
	deps.signal = func() error { signaled++; return nil }
	if err := runHTTPWith(context.Background(), []string{"disable"}, deps); err != nil {
		t.Fatal(err)
	}
	cfg, err := httpconfig.Load(deps.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Enabled {
		t.Fatal("disable left the door enabled")
	}
	if signaled != 1 {
		t.Fatalf("signals = %d", signaled)
	}
	if !strings.Contains(stdout.String(), "disabled") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestHTTPEnableDoesNotEchoArguments(t *testing.T) {
	deps, _, _, _, _ := testDeps(t)
	secretArg := "not-a-real-token-value"
	err := runHTTPWith(context.Background(), []string{"enable", secretArg}, deps)
	if err == nil || strings.Contains(err.Error(), secretArg) {
		t.Fatalf("enable echoed its argument: %v", err)
	}
}

func TestHTTPStatusReadsLiveDoorState(t *testing.T) {
	deps, vault, _, stdout, _ := testDeps(t)
	tok, err := keystore.GenerateHTTPToken()
	if err != nil {
		t.Fatal(err)
	}
	defer tok.Zero()
	_ = vault.Save(tok)
	stamp := time.Now().Add(-3 * time.Minute).Unix()
	if err := httpconfig.WriteDoorState(httpconfig.DoorStatePath(deps.configPath), httpconfig.DoorState{
		PID: os.Getpid(), Listening: true, Sessions: 4, UnlockUnix: stamp,
	}); err != nil {
		t.Fatal(err)
	}
	if err := runHTTPWith(context.Background(), []string{"status"}, deps); err != nil {
		t.Fatal(err)
	}
	out := stdout.String()
	if !strings.Contains(out, "sessions: 4") || !strings.Contains(out, "listening: true") || strings.Contains(out, "unlock age: none") {
		t.Fatalf("status = %q", out)
	}
	if strings.Contains(out, mustHex(t, tok)) {
		t.Fatal("status printed the token")
	}
}

func TestHTTPRevokeSignals(t *testing.T) {
	deps, vault, _, _, _ := testDeps(t)
	tok, err := keystore.GenerateHTTPToken()
	if err != nil {
		t.Fatal(err)
	}
	defer tok.Zero()
	_ = vault.Save(tok)
	var signaled int
	deps.signal = func() error { signaled++; return nil }
	if err := runHTTPWith(context.Background(), []string{"token", "revoke"}, deps); err != nil {
		t.Fatal(err)
	}
	if signaled != 1 || vault.has {
		t.Fatalf("signals=%d has=%v", signaled, vault.has)
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
	var signaled int
	deps.signal = func() error { signaled++; return nil }
	deps.hold = 250 * time.Millisecond
	start := time.Now()
	if err := runHTTPWith(context.Background(), []string{"token", "rotate"}, deps); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) < 200*time.Millisecond {
		t.Fatal("rotate returned before the clipboard hold; the clear would die with the process")
	}
	first, err := vault.Load()
	if err != nil {
		t.Fatal(err)
	}
	defer first.Zero()
	firstHex := mustHex(t, first)
	if board.value != "" {
		t.Fatalf("clipboard still holds %q after rotate returned", board.value)
	}
	if strings.Contains(stdout.String()+stderr.String(), firstHex) {
		t.Fatal("rotate wrote the token to output")
	}
	if !strings.Contains(stderr.String(), "Ctrl-C") || !strings.Contains(stderr.String(), "Clipboard cleared") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if signaled != 1 {
		t.Fatalf("rotate signals = %d, want 1", signaled)
	}

	// A value copied during the hold is left alone.
	deps.hold = 300 * time.Millisecond
	done := make(chan struct{})
	go func() {
		time.Sleep(40 * time.Millisecond)
		_ = board.Write("something the user copied later")
		close(done)
	}()
	if err := runHTTPWith(context.Background(), []string{"token", "rotate"}, deps); err != nil {
		t.Fatal(err)
	}
	<-done
	if board.value != "something the user copied later" {
		t.Fatalf("clear wiped a newer clipboard value: %q", board.value)
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
}

func TestHTTPRotateCtrlCClearsEarly(t *testing.T) {
	deps, _, board, _, stderr := testDeps(t)
	deps.hold = 5 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(40 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	if err := runHTTPWith(ctx, []string{"token", "rotate"}, deps); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("Ctrl-C did not end the clipboard hold")
	}
	if board.value != "" {
		t.Fatalf("clipboard = %q after Ctrl-C", board.value)
	}
	if !strings.Contains(stderr.String(), "Clipboard cleared") {
		t.Fatalf("stderr = %q", stderr.String())
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
	want := mustHex(t, tok)
	seen := make(chan string, 1)
	deps.hold = 250 * time.Millisecond
	go func() {
		time.Sleep(40 * time.Millisecond)
		cur, _ := board.Read()
		seen <- cur
	}()
	if err := runHTTPWith(context.Background(), []string{"token", "show"}, deps); err != nil {
		t.Fatal(err)
	}
	if got := <-seen; got != want {
		t.Fatalf("clipboard during the hold = %q, want the token", got)
	}
	if board.value != "" {
		t.Fatalf("clipboard after show returned = %q", board.value)
	}
	if strings.Contains(stdout.String()+stderr.String(), want) {
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
