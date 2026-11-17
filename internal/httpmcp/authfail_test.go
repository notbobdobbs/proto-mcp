package httpmcp

import (
	"bytes"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/audit"
	"github.com/just-an-oldsalt/proto-mcp/internal/httpconfig"
	"github.com/just-an-oldsalt/proto-mcp/internal/secret"
)

func TestAuthFailuresCloseTheListenerAndKeepTheFile(t *testing.T) {
	s, st, text, _ := testService(t)
	cfg := httpconfig.Default()
	cfg.Enabled = true
	cfg.AutoDisableAfterAuthFailures = 3
	cfg.Listen = freeLoopback(t)
	if err := httpconfig.Save(s.Path, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	if !s.Listening() {
		t.Fatal("door did not listen")
	}
	aw, err := audit.New(st.DB, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	s.Audit = aw
	var notes []string
	s.Notify = func(msg string) error {
		notes = append(notes, msg)
		return errors.New("osascript failed")
	}

	host := "127.0.0.1:4765"
	init := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	post(s, "", host, "", init)
	del := httptest.NewRequest(http.MethodDelete, "http://"+host+"/mcp", nil)
	del.Host = host
	del.RemoteAddr = "127.0.0.1:9"
	del.Header.Set("Authorization", "Bearer 00")
	s.ServeHTTP(httptest.NewRecorder(), del)
	q := httptest.NewRequest(http.MethodPost, "http://"+host+"/mcp?token=short", strings.NewReader(init))
	q.Host = host
	q.RemoteAddr = "127.0.0.1:9"
	q.Header.Set("Authorization", "Bearer "+text)
	s.ServeHTTP(httptest.NewRecorder(), q)

	if s.Listening() {
		t.Fatal("threshold left the listener open")
	}
	if _, err := net.DialTimeout("tcp", cfg.Listen, 200*time.Millisecond); err == nil {
		t.Fatal("dial succeeded after auto-disable")
	}
	info, err := os.Stat(s.Path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 0600", info.Mode().Perm())
	}
	body, err := os.ReadFile(s.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "enabled: false") || !strings.Contains(string(body), cfg.Listen) {
		t.Fatalf("http.yaml = %s", body)
	}
	loaded, err := httpconfig.Load(s.Path)
	if err != nil || loaded.Enabled || loaded.AutoDisableAfterAuthFailures != 3 {
		t.Fatalf("reloaded %+v err %v", loaded, err)
	}
	if len(notes) != 1 || strings.Contains(notes[0], text) || strings.Contains(notes[0], "Bearer") {
		t.Fatalf("notice = %v", notes)
	}
	var tool, args string
	if err := st.DB.QueryRow(`SELECT tool, args_json FROM audit_log WHERE tool = 'http_auto_disable'`).Scan(&tool, &args); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(args, text) || !strings.Contains(args, `"failures":3`) {
		t.Fatalf("audit args = %s", args)
	}

	// A later day does not turn the door back on.
	s.Now = func() time.Time { return time.Now().Add(48 * time.Hour) }
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if s.Listening() {
		t.Fatal("a new day re-enabled the door")
	}

	// Nothing in the daemon turns the file back on. The CLI enable
	// command is what writes enabled:true and zeros the count.
	if err := httpconfig.SetEnabled(s.Path, true); err != nil {
		t.Fatal(err)
	}
	if err := httpconfig.ResetAuthFailures(httpconfig.AuthStatePath(s.Path), time.Now()); err != nil {
		t.Fatal(err)
	}
	again, err := httpconfig.Load(s.Path)
	if err != nil || !again.Enabled {
		t.Fatalf("enable left %+v %v", again, err)
	}
	today := httpconfig.ReadAuthDay(httpconfig.AuthStatePath(s.Path), time.Now())
	if today.Failures != 0 || today.AutoDisabled || today.ClearedUnixNano == 0 {
		t.Fatalf("after enable %+v", today)
	}
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if !s.Listening() {
		t.Fatal("writing enabled:true did not listen")
	}
}

func TestAuthFailureCountResetsAtLocalMidnight(t *testing.T) {
	s, _, _, _ := testService(t)
	cfg := httpconfig.Default()
	cfg.Enabled = true
	cfg.AutoDisableAfterAuthFailures = 4
	cfg.Listen = freeLoopback(t)
	if err := httpconfig.Save(s.Path, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	s.Notify = func(string) error { return nil }
	now := time.Date(2026, 11, 16, 23, 30, 0, 0, time.Local)
	s.Now = func() time.Time { return now }
	host := "127.0.0.1:4765"
	for i := 0; i < 3; i++ {
		post(s, "", host, "", `{}`)
	}
	if !s.Listening() {
		t.Fatal("count below the threshold closed the door")
	}
	now = time.Date(2026, 11, 17, 0, 5, 0, 0, time.Local)
	post(s, "", host, "", `{}`)
	if !s.Listening() {
		t.Fatal("the first failure of a new day closed the door")
	}
	got := httpconfig.ReadAuthDay(httpconfig.AuthStatePath(s.Path), now)
	if got.Failures != 1 || got.Day != "2026-11-17" || got.AutoDisabled {
		t.Fatalf("new day = %+v", got)
	}
	old := httpconfig.ReadAuthDay(httpconfig.AuthStatePath(s.Path), time.Date(2026, 11, 16, 12, 0, 0, 0, time.Local))
	if old.Failures != 0 {
		t.Fatalf("yesterday still counts: %+v", old)
	}
}

func TestUnsavedAuthFailureStillClosesTheDoor(t *testing.T) {
	s, _, text, _ := testService(t)
	cfg := httpconfig.Default()
	cfg.Enabled = true
	cfg.AutoDisableAfterAuthFailures = 50
	cfg.Listen = freeLoopback(t)
	if err := httpconfig.Save(s.Path, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	authPath := httpconfig.AuthStatePath(s.Path)
	if err := os.Mkdir(authPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(authPath+"/blocker", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	var notes []string
	s.Notify = func(msg string) error {
		notes = append(notes, msg)
		return nil
	}
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	host := "127.0.0.1:4765"
	post(s, "", host, "", `{}`)
	if s.Listening() {
		t.Fatal("a counter write error left the listener up")
	}
	if _, err := net.DialTimeout("tcp", cfg.Listen, 200*time.Millisecond); err == nil {
		t.Fatal("dial succeeded after the counter write failed")
	}
	body, err := os.ReadFile(s.Path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(s.Path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 || !strings.Contains(string(body), "enabled: false") {
		t.Fatalf("mode %o yaml %s", info.Mode().Perm(), body)
	}
	if len(notes) != 1 || strings.Contains(notes[0], text) || strings.Contains(logs.String(), text) {
		t.Fatalf("notice %v log %s", notes, logs.String())
	}
	if !strings.Contains(logs.String(), "could not be saved") {
		t.Fatalf("log %s", logs.String())
	}
}

func TestKeychainReadErrorDoesNotCount(t *testing.T) {
	s, _, text, _ := testService(t)
	cfg := httpconfig.Default()
	cfg.Enabled = true
	cfg.AutoDisableAfterAuthFailures = 1
	cfg.Listen = freeLoopback(t)
	if err := httpconfig.Save(s.Path, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	secretHex := strings.Repeat("ab", 32)
	s.Token = func() (secret.Secret, error) {
		return secret.Secret{}, errors.New("keychain read failed near " + secretHex)
	}
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	host := "127.0.0.1:4765"
	for i := 0; i < authFailLimit; i++ {
		rec := post(s, text, host, "", `{}`)
		if rec.Code != http.StatusUnauthorized || rec.Body.Len() != 0 {
			t.Fatalf("try %d: code %d body %q", i, rec.Code, rec.Body.String())
		}
	}
	if post(s, text, host, "", `{}`).Code != http.StatusTooManyRequests {
		t.Fatal("keychain errors did not trip the per-minute limiter")
	}
	if !s.Listening() {
		t.Fatal("a keychain read error disabled the door")
	}
	got := httpconfig.ReadAuthDay(httpconfig.AuthStatePath(s.Path), time.Now())
	if got.Failures != 0 || got.AutoDisabled {
		t.Fatalf("counted a keychain error: %+v", got)
	}
	if strings.Contains(logs.String(), secretHex) || strings.Contains(logs.String(), text) {
		t.Fatalf("log leaked a secret: %s", logs.String())
	}
	if strings.Count(logs.String(), "could not read the bearer token") != 1 {
		t.Fatalf("log %s", logs.String())
	}
}

func TestHandEditDoesNotClearAnAutoDisable(t *testing.T) {
	s, _, _, _ := testService(t)
	cfg := httpconfig.Default()
	cfg.Enabled = true
	cfg.AutoDisableAfterAuthFailures = 1
	cfg.Listen = freeLoopback(t)
	if err := httpconfig.Save(s.Path, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	s.Notify = func(string) error { return nil }
	post(s, "", "127.0.0.1:4765", "", `{}`)
	if s.Listening() {
		t.Fatal("threshold left the listener up")
	}
	cfg.Enabled = true
	if err := httpconfig.Save(s.Path, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if s.Listening() {
		t.Fatal("a hand-edit and reload re-opened the door")
	}
	if err := httpconfig.ResetAuthFailures(httpconfig.AuthStatePath(s.Path), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if !s.Listening() {
		t.Fatal("http enable's clear did not allow the door to listen")
	}
}

func TestFailedDisableWritesStayClosedAcrossReload(t *testing.T) {
	s, _, _, _ := testService(t)
	cfg := httpconfig.Default()
	cfg.Enabled = true
	cfg.AutoDisableAfterAuthFailures = 50
	cfg.Listen = freeLoopback(t)
	if err := httpconfig.Save(s.Path, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(dirOf(s.Path), 0o700)
		s.Close()
	})
	s.Notify = func(string) error { return nil }
	dir := dirOf(s.Path)
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	post(s, "", "127.0.0.1:4765", "", `{}`)
	if s.Listening() {
		t.Fatal("unwritable config left the listener up")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// The yaml write failed, so the file can still say enabled.
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if s.Listening() {
		t.Fatal("reload re-opened the door after both disable writes failed")
	}
	loaded, err := httpconfig.Load(s.Path)
	if err != nil {
		t.Fatal(err)
	}
	loaded.Enabled = true
	if err := httpconfig.Save(s.Path, loaded); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if s.Listening() {
		t.Fatal("a hand-edit re-opened the door while the in-memory block stood")
	}
}

func dirOf(path string) string {
	i := strings.LastIndex(path, "/")
	return path[:i]
}
