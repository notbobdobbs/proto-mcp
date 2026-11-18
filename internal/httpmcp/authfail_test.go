package httpmcp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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
	if len(notes) != 1 || strings.Contains(notes[0], text) || strings.Contains(notes[0], "Bearer") || !strings.Contains(notes[0], "http status --debug") {
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

func TestRestartContinuesTodaysAuthFailureCount(t *testing.T) {
	s, _, _, _ := testService(t)
	cfg := httpconfig.Default()
	cfg.Enabled = true
	cfg.AutoDisableAfterAuthFailures = 2
	cfg.Listen = freeLoopback(t)
	if err := httpconfig.Save(s.Path, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	s.Notify = func(string) error { return nil }
	post(s, "", "127.0.0.1:4765", "", `{}`)
	if !s.Listening() {
		t.Fatal("the first of two failures closed the door")
	}
	got := httpconfig.ReadAuthDay(httpconfig.AuthStatePath(s.Path), time.Now())
	if got.Failures != 1 {
		t.Fatalf("stored count after one failure = %+v", got)
	}
	s.Close()

	// A new process on the same files. Memory starts empty; the stored
	// count for today has to come back with it.
	s2 := New(s.MCP, s.Path, s.Token)
	s2.Notify = func(string) error { return nil }
	t.Cleanup(s2.Close)
	if err := s2.Reload(); err != nil {
		t.Fatal(err)
	}
	if !s2.Listening() {
		t.Fatal("restart closed the door with one failure stored")
	}
	post(s2, "", "127.0.0.1:4765", "", `{}`)
	got = httpconfig.ReadAuthDay(httpconfig.AuthStatePath(s.Path), time.Now())
	if got.Failures != 2 {
		t.Fatalf("stored count after restart = %+v", got)
	}
	if s2.Listening() {
		t.Fatal("the second failure after restart left the listener open")
	}
}

func TestAuthWarnFiresOnceAcrossRestartAndResetsNextDay(t *testing.T) {
	s, st, _, _ := testService(t)
	cfg := httpconfig.Default()
	cfg.Enabled = true
	cfg.WarnAfterAuthFailures = 2
	cfg.AutoDisableAfterAuthFailures = 10
	cfg.Listen = freeLoopback(t)
	if err := httpconfig.Save(s.Path, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	aw, err := audit.New(st.DB, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	s.Audit = aw
	token := strings.Repeat("cd", 32)
	var notes []string
	s.Notify = func(msg string) error {
		notes = append(notes, msg)
		return nil
	}
	fail := func(svc *Service) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:4765/mcp", strings.NewReader(`{}`))
		req.Host = "127.0.0.1:4765"
		req.RemoteAddr = "127.0.0.1:9"
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("User-Agent", "bot\x00 "+token+" tail")
		req.Header.Set("Tailscale-Funnel-Request", "?1")
		req.Header.Set("X-Forwarded-For", token+", 100.64.1.8")
		req.Header.Set("Tailscale-Client-Ip", "203.0.113.50")
		svc.ServeHTTP(httptest.NewRecorder(), req)
	}
	fail(s)
	fail(s)
	fail(s)
	if len(notes) != 1 || !strings.Contains(notes[0], "still on") || !strings.Contains(notes[0], "http status --debug") || !strings.Contains(notes[0], "wrong token") || !strings.Contains(notes[0], "forwarded 100.64.1.8") || strings.Contains(notes[0], "203.0.113.50") {
		t.Fatalf("warning = %v", notes)
	}
	if !s.Listening() {
		t.Fatal("the warning closed the door")
	}
	assertNoToken(t, token, notes[0])
	var args string
	if err := st.DB.QueryRow(`SELECT args_json FROM audit_log WHERE tool = 'http_auth_warn'`).Scan(&args); err != nil {
		t.Fatal(err)
	}
	assertNoToken(t, token, args)
	detail := httpconfig.FormatAuthDebug(httpconfig.ReadAuthDay(httpconfig.AuthStatePath(s.Path), time.Now()))
	assertNoToken(t, token, detail)
	if !strings.Contains(detail, "wrong token") || !strings.Contains(detail, "forwarded 100.64.1.8") || strings.Contains(detail, "203.0.113.50") || !strings.Contains(detail, "POST /mcp") || !strings.Contains(detail, "first:") || !strings.Contains(detail, "peak per minute:") || !strings.Contains(detail, "sample:") {
		t.Fatalf("detail = %s", detail)
	}
	raw, err := os.ReadFile(httpconfig.AuthStatePath(s.Path))
	if err != nil {
		t.Fatal(err)
	}
	assertNoToken(t, token, string(raw))
	s.Close()

	s2 := New(s.MCP, s.Path, s.Token)
	s2.Audit = aw
	var again []string
	s2.Notify = func(msg string) error {
		again = append(again, msg)
		return nil
	}
	t.Cleanup(s2.Close)
	if err := s2.Reload(); err != nil {
		t.Fatal(err)
	}
	fail(s2)
	if len(again) != 0 {
		t.Fatalf("restart re-fired the warning: %v", again)
	}
	if !s2.Listening() {
		t.Fatal("restart closed the door")
	}

	next := time.Now().Add(48 * time.Hour)
	s2.Now = func() time.Time { return next }
	fail(s2)
	fail(s2)
	if len(again) != 1 || !strings.Contains(again[0], "still on") {
		t.Fatalf("next day warning = %v", again)
	}
	assertNoToken(t, token, again[0])
}

func TestNoAuthWarnWhenDisableComesFirst(t *testing.T) {
	for _, lim := range [][2]int{{2, 5}, {4, 4}} {
		disable, warn := lim[0], lim[1]
		s, _, _, _ := testService(t)
		cfg := httpconfig.Default()
		cfg.Enabled = true
		cfg.WarnAfterAuthFailures = warn
		cfg.AutoDisableAfterAuthFailures = disable
		cfg.Listen = freeLoopback(t)
		if err := httpconfig.Save(s.Path, cfg); err != nil {
			t.Fatal(err)
		}
		if err := s.Reload(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
		var notes []string
		s.Notify = func(msg string) error {
			notes = append(notes, msg)
			return errors.New("osascript failed")
		}
		for i := 0; i < disable; i++ {
			post(s, "", "127.0.0.1:4765", "", `{}`)
		}
		if s.Listening() {
			t.Fatalf("disable %d warn %d left the door open", disable, warn)
		}
		for _, n := range notes {
			if strings.Contains(n, "still on") {
				t.Fatalf("warned even though disable %d is at or below warn %d: %s", disable, warn, n)
			}
		}
		got := httpconfig.ReadAuthDay(httpconfig.AuthStatePath(s.Path), time.Now())
		if got.Warned {
			t.Fatalf("warned flag set when disable %d warn %d skips the warning", disable, warn)
		}
	}
}

func TestAuthWarnFailureDoesNotChangeAuth(t *testing.T) {
	s, _, _, _ := testService(t)
	cfg := httpconfig.Default()
	cfg.Enabled = true
	cfg.WarnAfterAuthFailures = 1
	cfg.AutoDisableAfterAuthFailures = 10
	cfg.Listen = freeLoopback(t)
	if err := httpconfig.Save(s.Path, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	calls := 0
	s.Notify = func(string) error {
		calls++
		return errors.New("osascript failed")
	}
	post(s, "", "127.0.0.1:4765", "", `{}`)
	if !s.Listening() {
		t.Fatal("a failed warning closed the door")
	}
	got := httpconfig.ReadAuthDay(httpconfig.AuthStatePath(s.Path), time.Now())
	if got.Failures != 1 || got.Warned || calls != 1 {
		t.Fatalf("after failed warning failures=%d warned=%v calls=%d", got.Failures, got.Warned, calls)
	}
	s.Close()

	s2 := New(s.MCP, s.Path, s.Token)
	s2.Notify = func(string) error {
		calls++
		return nil
	}
	t.Cleanup(s2.Close)
	if err := s2.Reload(); err != nil {
		t.Fatal(err)
	}
	post(s2, "", "127.0.0.1:4765", "", `{}`)
	got = httpconfig.ReadAuthDay(httpconfig.AuthStatePath(s.Path), time.Now())
	if !s2.Listening() || got.Failures != 2 || !got.Warned || calls != 2 {
		t.Fatalf("restart retry failures=%d warned=%v calls=%d listening=%v", got.Failures, got.Warned, calls, s2.Listening())
	}
	post(s2, "", "127.0.0.1:4765", "", `{}`)
	if calls != 2 {
		t.Fatalf("warned flag did not stop the next try: %d", calls)
	}
}

func TestAuthTraceSkipsTheDailyCountForOriginAndRateLimit(t *testing.T) {
	s, _, _, _ := testService(t)
	cfg := httpconfig.Default()
	cfg.Enabled = true
	cfg.AutoDisableAfterAuthFailures = 10000
	cfg.WarnAfterAuthFailures = 500
	cfg.Listen = freeLoopback(t)
	if err := httpconfig.Save(s.Path, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	now := time.Now()
	s.Now = func() time.Time { return now }
	token := strings.Repeat("ef", 32)
	host := "127.0.0.1:4765"
	origin := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:4765/mcp", strings.NewReader(`{}`))
	origin.Host = host
	origin.RemoteAddr = "127.0.0.1:9"
	origin.Header.Set("Origin", "http://evil.example/"+token)
	origin.Header.Set("User-Agent", "origin "+token)
	s.ServeHTTP(httptest.NewRecorder(), origin)
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:4765/mcp?access_token="+token, strings.NewReader(`{}`))
	req.Host = host
	req.RemoteAddr = "127.0.0.1:9"
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "ua "+token)
	req.Header.Set("Tailscale-Funnel-Request", "?1")
	req.Header.Set("X-Forwarded-For", token+", 203.0.113.9")
	req.Header.Set("Tailscale-Client-Ip", "198.51.100.23")
	s.ServeHTTP(httptest.NewRecorder(), req)
	basic := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:4765/mcp", strings.NewReader(`{}`))
	basic.Host = host
	basic.RemoteAddr = "127.0.0.1:9"
	basic.Header.Set("Authorization", "Basic "+token)
	s.ServeHTTP(httptest.NewRecorder(), basic)
	wrong := strings.Repeat("12", 32)
	post(s, wrong, host, "", `{}`)
	for i := 0; i < authFailLimit-3; i++ {
		post(s, "", host, "", `{}`)
	}
	post(s, "", host, "", `{}`)
	now = now.Add(time.Second)
	post(s, "", host, "", `{}`)

	got := httpconfig.ReadAuthDay(httpconfig.AuthStatePath(s.Path), now)
	if got.Failures != authFailLimit {
		t.Fatalf("failures = %d, origin and rate-limit must not count", got.Failures)
	}
	if got.Trace.Reasons[httpconfig.ReasonQueryToken] != 1 || got.Trace.Reasons[httpconfig.ReasonBadScheme] != 1 || got.Trace.Reasons[httpconfig.ReasonWrongToken] != 1 || got.Trace.Reasons[httpconfig.ReasonMissingHeader] != authFailLimit-3 || got.Trace.Reasons[httpconfig.ReasonRateLimited] != 2 || got.Trace.Reasons[httpconfig.ReasonBadOrigin] != 1 {
		t.Fatalf("reasons = %#v", got.Trace.Reasons)
	}
	assertNoToken(t, wrong, httpconfig.FormatAuthDebug(got))
	if got.Trace.Sources["forwarded 203.0.113.9"] != 1 || got.Trace.Sources["remote 127.0.0.1"] == 0 || got.Trace.Sources["forwarded 198.51.100.23"] != 0 {
		t.Fatalf("sources = %#v", got.Trace.Sources)
	}
	if !s.Listening() {
		t.Fatal("trace-only rejections closed the door")
	}
	blob := httpconfig.FormatAuthDebug(got)
	raw, err := os.ReadFile(httpconfig.AuthStatePath(s.Path))
	if err != nil {
		t.Fatal(err)
	}
	assertNoToken(t, token, blob+"\n"+string(raw))
	if strings.Contains(string(raw), "198.51.100.23") {
		t.Fatal("forged Tailscale-Client-Ip was stored")
	}
}

func TestForgedTailscaleClientIPIsIgnored(t *testing.T) {
	s, _, _, _ := testService(t)
	cfg := httpconfig.Default()
	cfg.Enabled = true
	cfg.AutoDisableAfterAuthFailures = 10000
	cfg.WarnAfterAuthFailures = 500
	cfg.Listen = freeLoopback(t)
	if err := httpconfig.Save(s.Path, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	host := "127.0.0.1:4765"
	forged := "203.0.113.50"
	req := httptest.NewRequest(http.MethodPost, "http://"+host+"/mcp", strings.NewReader(`{}`))
	req.Host = host
	req.RemoteAddr = "127.0.0.1:9"
	req.Header.Set("Tailscale-Client-Ip", forged)
	req.Header.Set("X-Forwarded-For", "198.51.100.7")
	s.ServeHTTP(httptest.NewRecorder(), req)
	got := httpconfig.ReadAuthDay(httpconfig.AuthStatePath(s.Path), time.Now())
	blob := httpconfig.FormatAuthDebug(got)
	if strings.Contains(blob, forged) || strings.Contains(blob, "198.51.100.7") || !strings.Contains(blob, "remote 127.0.0.1") {
		t.Fatalf("unmarked request used a client header: %s", blob)
	}
	marked := httptest.NewRequest(http.MethodPost, "http://"+host+"/mcp", strings.NewReader(`{}`))
	marked.Host = host
	marked.RemoteAddr = "127.0.0.1:9"
	marked.Header.Set("Tailscale-Funnel-Request", "?1")
	marked.Header.Set("Tailscale-Client-Ip", forged)
	marked.Header.Set("X-Forwarded-For", "198.51.100.7, 203.0.113.9")
	s.ServeHTTP(httptest.NewRecorder(), marked)
	got = httpconfig.ReadAuthDay(httpconfig.AuthStatePath(s.Path), time.Now())
	blob = httpconfig.FormatAuthDebug(got)
	if !strings.Contains(blob, "forwarded 203.0.113.9") || strings.Contains(blob, forged) || strings.Contains(blob, "198.51.100.7") {
		t.Fatalf("funnel source = %s", blob)
	}
}

func TestOriginDetailIsSavedAboutOnceASecond(t *testing.T) {
	s, _, _, _ := testService(t)
	cfg := httpconfig.Default()
	cfg.Enabled = true
	cfg.AutoDisableAfterAuthFailures = 10000
	cfg.WarnAfterAuthFailures = 500
	cfg.Listen = freeLoopback(t)
	if err := httpconfig.Save(s.Path, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	now := time.Now()
	s.Now = func() time.Time { return now }
	host := "127.0.0.1:4765"
	path := httpconfig.AuthStatePath(s.Path)
	origin := func() {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "http://"+host+"/mcp", strings.NewReader(`{}`))
		req.Host = host
		req.RemoteAddr = "127.0.0.1:9"
		req.Header.Set("Origin", "http://evil.example")
		s.ServeHTTP(httptest.NewRecorder(), req)
	}
	origin()
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		origin()
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("bad Origin rewrote the detail file within the same second")
	}
	got := httpconfig.ReadAuthDay(path, now)
	if got.Failures != 0 || got.Trace.Reasons[httpconfig.ReasonBadOrigin] != 1 {
		t.Fatalf("during the second %+v failures %d", got.Trace.Reasons, got.Failures)
	}
	now = now.Add(time.Second)
	origin()
	got = httpconfig.ReadAuthDay(path, now)
	if got.Failures != 0 || got.Trace.Reasons[httpconfig.ReasonBadOrigin] != 22 || !s.Listening() {
		t.Fatalf("after a second %+v listening %v", got.Trace.Reasons, s.Listening())
	}
	now = now.Add(time.Millisecond)
	origin()
	post(s, "", host, "", `{}`)
	got = httpconfig.ReadAuthDay(path, now)
	if got.Failures != 1 || got.Trace.Reasons[httpconfig.ReasonBadOrigin] != 23 {
		t.Fatalf("counted failure did not save immediately: failures %d reasons %+v", got.Failures, got.Trace.Reasons)
	}

	now = now.Add(2 * time.Minute)
	for i := 0; i < authFailLimit; i++ {
		post(s, "", host, "", `{}`)
	}
	before := httpconfig.ReadAuthDay(path, now)
	for i := 0; i < 5; i++ {
		post(s, "", host, "", `{}`)
	}
	held := httpconfig.ReadAuthDay(path, now)
	if held.Trace.Reasons[httpconfig.ReasonRateLimited] != before.Trace.Reasons[httpconfig.ReasonRateLimited] || held.Failures != before.Failures {
		t.Fatalf("lockout rewrote the file within the second: before %+v held %+v", before.Trace.Reasons, held.Trace.Reasons)
	}
	now = now.Add(time.Second)
	post(s, "", host, "", `{}`)
	got = httpconfig.ReadAuthDay(path, now)
	if got.Failures != before.Failures || got.Trace.Reasons[httpconfig.ReasonRateLimited] != before.Trace.Reasons[httpconfig.ReasonRateLimited]+6 {
		t.Fatalf("lockout flush failures %d reasons %+v", got.Failures, got.Trace.Reasons)
	}
	if !s.Listening() {
		t.Fatal("saving the detail closed the door")
	}
}

func TestWrongHostDoesNotReadTheTokenOrCount(t *testing.T) {
	s, _, text, _ := testService(t)
	reads := 0
	prev := s.Token
	s.Token = func() (secret.Secret, error) {
		reads++
		return prev()
	}
	req := httptest.NewRequest(http.MethodPost, "http://evil.example/mcp", strings.NewReader(`{}`))
	req.Host = "evil.example"
	req.RemoteAddr = "127.0.0.1:9"
	req.Header.Set("Authorization", "Bearer "+text)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d", rec.Code)
	}
	if reads != 0 {
		t.Fatalf("token reads %d", reads)
	}
	got := httpconfig.ReadAuthDay(httpconfig.AuthStatePath(s.Path), time.Now())
	if got.Failures != 0 || len(got.Trace.Reasons) != 0 || len(got.Trace.Sample) != 0 {
		t.Fatalf("host mismatch was recorded: %+v", got)
	}
}

func TestAuditBeginFailureLeavesTheListenerAsItWas(t *testing.T) {
	s, st, _, _ := testService(t)
	cfg := httpconfig.Default()
	cfg.Enabled = true
	cfg.WarnAfterAuthFailures = 1
	cfg.AutoDisableAfterAuthFailures = 10
	cfg.Listen = freeLoopback(t)
	if err := httpconfig.Save(s.Path, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	aw, err := audit.New(st.DB, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.DB.Close(); err != nil {
		t.Fatal(err)
	}
	s.Audit = aw
	s.Notify = func(string) error { return nil }
	if !s.Listening() {
		t.Fatal("warning path was not listening")
	}
	post(s, "", "127.0.0.1:4765", "", `{}`)
	if !s.Listening() {
		t.Fatal("a failed audit Begin closed the listener on the warning path")
	}
	s.Close()

	s2, st2, _, _ := testService(t)
	cfg.AutoDisableAfterAuthFailures = 1
	cfg.Listen = freeLoopback(t)
	if err := httpconfig.Save(s2.Path, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s2.Reload(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s2.Close)
	aw, err = audit.New(st2.DB, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := st2.DB.Close(); err != nil {
		t.Fatal(err)
	}
	s2.Audit = aw
	s2.Notify = func(string) error { return nil }
	if !s2.Listening() {
		t.Fatal("disable path was not listening")
	}
	post(s2, "", "127.0.0.1:4765", "", `{}`)
	if s2.Listening() {
		t.Fatal("the disable threshold left the listener up")
	}
	if err := s2.Reload(); err != nil {
		t.Fatal(err)
	}
	if s2.Listening() {
		t.Fatal("a failed audit Begin reopened the listener")
	}
}

func assertNoToken(t *testing.T, token, text string) {
	t.Helper()
	sum := sha256.Sum256([]byte(token))
	hash := hex.EncodeToString(sum[:])
	lower := strings.ToLower(text)
	if strings.Contains(text, token) || strings.Contains(text, token[:8]) || strings.Contains(lower, hash) || strings.Contains(lower, "bearer") || strings.Contains(lower, "authorization") {
		t.Fatalf("output contains a token or Authorization material: %s", text)
	}
}

func dirOf(path string) string {
	i := strings.LastIndex(path, "/")
	return path[:i]
}
