package httpmcp

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/audit"
	"github.com/just-an-oldsalt/proto-mcp/internal/httpconfig"
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
	if today.Failures != 0 || !today.AutoDisabled {
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
