package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/approval"
	"github.com/just-an-oldsalt/proto-mcp/internal/httpconfig"
	"github.com/just-an-oldsalt/proto-mcp/internal/httpmcp"
	"github.com/just-an-oldsalt/proto-mcp/internal/keystore"
	"github.com/just-an-oldsalt/proto-mcp/internal/mcperrors"
	"github.com/just-an-oldsalt/proto-mcp/internal/policy"
	"github.com/just-an-oldsalt/proto-mcp/internal/secret"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

// clipboardHold is how long a copied token is left on the clipboard
// before a compare-and-clear. About 60 seconds.
const clipboardHold = 60 * time.Second

// screenLockOffWarning is printed by `http enable` and by doctor.
// It does not block either command.
const screenLockOffWarning = "screen lock is off. That is an accepted risk and does not block the remote door. The 8-hour unlock clock and turning the tunnel off are the backstops."

// screenLockOn reports whether macOS asks for a password when the
// screen locks. A failed read is treated as off (not 1). Tests
// replace this.
var screenLockOn = defaultScreenLockOn

func defaultScreenLockOn() bool {
	out, err := exec.Command("defaults", "read", "com.apple.screensaver", "askForPassword").Output()
	if err != nil {
		return false
	}
	return string(bytes.TrimSpace(out)) == "1"
}

// tokenVault is the remote-token store. Production uses the Keychain.
// Tests use a memory fake. Logout does not go through this interface.
type tokenVault interface {
	Load() (secret.Secret, error)
	Save(secret.Secret) error
	Delete() error
}

type keychainTokenVault struct{}

func (keychainTokenVault) Load() (secret.Secret, error) { return keystore.LoadHTTPToken() }
func (keychainTokenVault) Save(s secret.Secret) error   { return keystore.SaveHTTPToken(s) }
func (keychainTokenVault) Delete() error                { return keystore.DeleteHTTPToken() }

// pasteboard is the clipboard. Write puts the token there. Clear
// runs later only when Read still returns that same text.
type pasteboard interface {
	Read() (string, error)
	Write(string) error
	Clear() error
}

type httpDeps struct {
	vault      tokenVault
	board      pasteboard
	approve    func(context.Context) error
	screenLock func() bool
	signal     func() error
	configPath string
	stdout     io.Writer
	stderr     io.Writer
	// hold is how long the process stays up after copying the token.
	// Zero means clipboardHold. Tests set a short real wait; they do
	// not replace the wait with a callback.
	hold time.Duration
}

func (d *httpDeps) fill() {
	if d.stdout == nil {
		d.stdout = os.Stdout
	}
	if d.stderr == nil {
		d.stderr = os.Stderr
	}
	if d.screenLock == nil {
		d.screenLock = func() bool { return screenLockOn() }
	}
	if d.signal == nil {
		d.signal = signalDaemons
	}
	if d.hold <= 0 {
		d.hold = clipboardHold
	}
	if d.approve == nil {
		d.approve = approveTokenShow
	}
	if d.configPath == "" {
		if dir, err := appSupportDir(); err == nil {
			d.configPath = filepath.Join(dir, "http.yaml")
		}
	}
	if d.vault == nil {
		d.vault = keychainTokenVault{}
	}
}

func runHTTP(ctx context.Context, args []string) error {
	return runHTTPWith(ctx, args, httpDeps{})
}

func runHTTPWith(ctx context.Context, args []string, deps httpDeps) error {
	deps.fill()
	if len(args) == 0 {
		return errors.New("usage: protonmcp http {enable|disable|status|token rotate|token revoke|token show}")
	}
	switch args[0] {
	case "enable":
		return deps.enable(args[1:])
	case "disable":
		return deps.disable(args[1:])
	case "status":
		return deps.status(args[1:])
	case "activity":
		return runHTTPActivity(args[1:])
	case "token":
		return deps.token(ctx, args[1:])
	default:
		return fmt.Errorf("unknown http subcommand: %s", args[0])
	}
}

func (d httpDeps) enable(args []string) error {
	if len(args) > 0 {
		return errors.New("http enable takes no arguments")
	}
	if d.configPath == "" {
		return errors.New("http enable: no config path")
	}
	tok, err := d.vault.Load()
	if err != nil || len(tok.Bytes()) != keystore.HTTPTokenLen {
		tok.Zero()
		return errors.New("http enable refused: no remote token is stored. Run `protonmcp http token rotate` on a Mac first")
	}
	tok.Zero()
	cfg, err := httpconfig.Load(d.configPath)
	if err != nil {
		return err
	}
	cfg.Enabled = true
	if err := httpconfig.Save(d.configPath, cfg); err != nil {
		return err
	}
	if !d.screenLock() {
		fmt.Fprintln(d.stderr, screenLockOffWarning)
	}
	if err := d.signal(); err != nil {
		fmt.Fprintf(d.stderr, "warning: could not signal the daemon: %v\n", err)
	}
	fmt.Fprintln(d.stdout, "Remote door config enabled.")
	return nil
}

func (d httpDeps) disable(args []string) error {
	if len(args) > 0 {
		return errors.New("http disable takes no arguments")
	}
	if d.configPath == "" {
		return errors.New("http disable: no config path")
	}
	// Do not parse the old file. A broken http.yaml must still become
	// enabled: false so the daemon can close the listener.
	if err := httpconfig.WriteDisabled(d.configPath); err != nil {
		return err
	}
	if err := d.signal(); err != nil {
		fmt.Fprintf(d.stderr, "warning: could not signal the daemon: %v\n", err)
	}
	fmt.Fprintln(d.stdout, "Remote door config disabled.")
	return nil
}

func (d httpDeps) status(args []string) error {
	if len(args) > 0 {
		return errors.New("http status takes no arguments")
	}
	cfg, cfgErr := httpconfig.Load(d.configPath)
	tokenLine := "absent"
	tok, err := d.vault.Load()
	if err == nil && len(tok.Bytes()) == keystore.HTTPTokenLen {
		tokenLine = "present"
	}
	tok.Zero()
	live := httpconfig.ReadLiveDoorState(httpconfig.DoorStatePath(d.configPath))
	enabled := "false"
	listen := ""
	if cfgErr == nil {
		enabled = fmt.Sprintf("%t", cfg.Enabled)
		listen = cfg.Listen
	} else {
		enabled = "unreadable"
	}
	fmt.Fprintf(d.stdout, "enabled: %s\nlisten: %s\ntoken: %s\nsessions: %d\nunlock age: %s\nlistening: %t\n",
		enabled, listen, tokenLine, live.Sessions, httpconfig.FormatUnlockAge(live.UnlockUnix, time.Now()), live.Listening)
	return cfgErr
}

func (d *httpDeps) token(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: protonmcp http token {rotate|revoke|show}")
	}
	switch args[0] {
	case "rotate":
		return d.rotate(ctx, args[1:])
	case "revoke":
		return d.revoke(args[1:])
	case "show":
		return d.show(ctx, args[1:])
	default:
		return fmt.Errorf("unknown http token subcommand: %s", args[0])
	}
}

func (d *httpDeps) needBoard() error {
	if d.board != nil {
		return nil
	}
	board, err := platformPasteboard()
	if err != nil {
		return err
	}
	d.board = board
	return nil
}

func (d *httpDeps) rotate(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return errors.New("http token rotate takes no arguments and does not accept the token on the command line")
	}
	if err := d.needBoard(); err != nil {
		return err
	}
	tok, err := keystore.GenerateHTTPToken()
	if err != nil {
		return err
	}
	defer tok.Zero()
	if err := d.vault.Save(tok); err != nil {
		return err
	}
	if err := d.signal(); err != nil {
		fmt.Fprintf(d.stderr, "warning: could not signal the daemon: %v\n", err)
	}
	text, err := keystore.EncodeHTTPToken(tok.Bytes())
	if err != nil {
		return err
	}
	fmt.Fprintln(d.stdout, "Remote token replaced. It is on the clipboard.")
	if err := d.copyToken(ctx, text); err != nil {
		return errors.New("remote token was replaced but the clipboard copy failed")
	}
	return nil
}

func (d *httpDeps) revoke(args []string) error {
	if len(args) > 0 {
		return errors.New("http token revoke takes no arguments and does not accept the token on the command line")
	}
	if err := d.vault.Delete(); err != nil {
		return err
	}
	if err := d.signal(); err != nil {
		fmt.Fprintf(d.stderr, "warning: could not signal the daemon: %v\n", err)
	}
	fmt.Fprintln(d.stdout, "Remote token revoked.")
	return nil
}

func (d *httpDeps) show(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return errors.New("http token show takes no arguments")
	}
	if err := d.needBoard(); err != nil {
		return err
	}
	if err := d.approve(ctx); err != nil {
		return err
	}
	tok, err := d.vault.Load()
	if err != nil {
		return err
	}
	defer tok.Zero()
	text, err := keystore.EncodeHTTPToken(tok.Bytes())
	if err != nil {
		return err
	}
	fmt.Fprintln(d.stdout, "Remote token copied to the clipboard.")
	if err := d.copyToken(ctx, text); err != nil {
		return errors.New("could not copy the remote token to the clipboard")
	}
	return nil
}

// copyToken writes the token and then blocks until the hold elapses
// or ctx is cancelled (Ctrl-C). The clear runs in this process. A
// timer scheduled after return would die when main exits.
func (d *httpDeps) copyToken(ctx context.Context, text string) error {
	if err := d.board.Write(text); err != nil {
		return err
	}
	hold := d.hold
	if hold <= 0 {
		hold = clipboardHold
	}
	fmt.Fprintf(d.stderr, "The token is on the clipboard. It will be cleared in %s. Press Ctrl-C to clear it now.\n", hold.Round(time.Second))
	timer := time.NewTimer(hold)
	defer timer.Stop()
	var tick *time.Ticker
	var tickC <-chan time.Time
	if hold >= time.Second {
		tick = time.NewTicker(time.Second)
		defer tick.Stop()
		tickC = tick.C
	}
	left := hold
	for {
		select {
		case <-ctx.Done():
			d.clearIfOurs(text)
			fmt.Fprintln(d.stderr, "Clipboard cleared.")
			return nil
		case <-tickC:
			left -= time.Second
			if left >= time.Second {
				fmt.Fprintf(d.stderr, "Clipboard clears in %s.\n", left.Round(time.Second))
			}
		case <-timer.C:
			d.clearIfOurs(text)
			fmt.Fprintln(d.stderr, "Clipboard cleared.")
			return nil
		}
	}
}

func (d *httpDeps) clearIfOurs(text string) {
	cur, err := d.board.Read()
	if err != nil || len(cur) != len(text) {
		return
	}
	if subtle.ConstantTimeCompare([]byte(cur), []byte(text)) != 1 {
		return
	}
	_ = d.board.Clear()
}

func runHTTPActivity(args []string) error {
	fs := flag.NewFlagSet("http activity", flag.ContinueOnError)
	dbPath := fs.String("db", "", "path to the local mirror")
	ids := fs.Bool("ids", false, "also print message ids")
	if err := fs.Parse(args); err != nil {
		return err
	}
	path := *dbPath
	if path == "" {
		var err error
		path, err = store.DefaultPath()
		if err != nil {
			return err
		}
	}
	st, err := store.Open(path)
	if err != nil {
		return err
	}
	defer st.Close()
	text, err := httpmcp.ActivityText(st.DB, time.Now(), *ids)
	if err != nil {
		return err
	}
	fmt.Print(text)
	return nil
}

// httpTokenPresent reports whether a 32-byte remote token is stored.
// It never returns the token bytes. Tests replace it.
var httpTokenPresent = func() bool {
	tok, err := keystore.LoadHTTPToken()
	if err != nil {
		return false
	}
	defer tok.Zero()
	return len(tok.Bytes()) == keystore.HTTPTokenLen
}

func checkHTTP(r *report) {
	dir, err := appSupportDir()
	if err != nil {
		r.add("http", stateWarn, "cannot locate http.yaml", "")
		return
	}
	cfg, err := httpconfig.Load(filepath.Join(dir, "http.yaml"))
	if err != nil {
		r.add("http", stateWarn, "http.yaml is not usable; the door stays off", "fix http.yaml")
		return
	}
	line := "off"
	if cfg.Enabled {
		line = "on, listen " + cfg.Listen
	}
	if httpTokenPresent() {
		line += ", token present"
	} else {
		line += ", token absent"
	}
	r.add("http", stateOK, line, "")
}

func checkScreenLock(r *report) {
	if screenLockOn() {
		r.add("screen lock", stateOK, "askForPassword is on", "")
		return
	}
	r.add("screen lock", stateWarn, screenLockOffWarning, "")
}

func signalDaemons() error {
	pids, err := policy.FindRunningPIDs()
	if err != nil {
		if errors.Is(err, policy.ErrNotRunning) {
			return nil
		}
		return err
	}
	for _, pid := range pids {
		p, err := os.FindProcess(pid)
		if err != nil {
			continue
		}
		_ = p.Signal(syscall.SIGHUP)
	}
	return nil
}

func approveTokenShow(ctx context.Context) error {
	path, err := approval.ResolveHelperPath(os.Args[0])
	if err != nil {
		return err
	}
	return runTokenShowHelper(ctx, path)
}

func runTokenShowHelper(ctx context.Context, path string) error {
	payload, err := json.Marshal(struct {
		Title   string `json:"title"`
		Body    string `json:"body"`
		Caller  string `json:"caller"`
		Confirm bool   `json:"confirm"`
	}{
		Title:   "Copy the remote token to the clipboard?",
		Body:    "This copies the remote door token onto the clipboard for about 60 seconds. It does not approve sending mail.",
		Caller:  "protonmcp http token show",
		Confirm: true,
	})
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, path)
	cmd.Stdin = bytes.NewReader(payload)
	var stderr, stdout bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &stdout
	err = cmd.Run()
	if err == nil {
		return nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return fmt.Errorf("%w: remote token was not copied", mcperrors.ErrUserCanceled)
	}
	return fmt.Errorf("touch id helper failed: %w", err)
}
