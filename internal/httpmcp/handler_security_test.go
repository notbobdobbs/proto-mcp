package httpmcp

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/audit"
	"github.com/just-an-oldsalt/proto-mcp/internal/caller"
	"github.com/just-an-oldsalt/proto-mcp/internal/httpconfig"
	"github.com/just-an-oldsalt/proto-mcp/internal/keystore"
	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	"github.com/just-an-oldsalt/proto-mcp/internal/secret"
)

func TestQueryBearerAndDeleteShareTheAuthBucket(t *testing.T) {
	s, _, text, calls := testService(t)
	host := "127.0.0.1:4765"
	init := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"synthetic","version":"0"}}}`
	hex64 := strings.Repeat("ab", 32)

	queries := []string{
		"?token=short",
		"?access_token=",
		"?authorization=nope",
		"?bearer=x",
		"?note=" + hex64,
		"?note=Bearer%20" + text,
	}
	for _, q := range queries {
		req := httptest.NewRequest(http.MethodPost, "http://"+host+"/mcp"+q, strings.NewReader(init))
		req.Host = host
		req.RemoteAddr = "127.0.0.1:9"
		req.Header.Set("Authorization", "Bearer "+text)
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized || rec.Body.Len() != 0 {
			t.Fatalf("%s: code %d body %q", q, rec.Code, rec.Body.String())
		}
	}
	// An unrelated query is not a bearer.
	ok := httptest.NewRequest(http.MethodPost, "http://"+host+"/mcp?x=1", strings.NewReader(init))
	ok.Host = host
	ok.RemoteAddr = "127.0.0.1:9"
	ok.Header.Set("Authorization", "Bearer "+text)
	okRec := httptest.NewRecorder()
	s.ServeHTTP(okRec, ok)
	if okRec.Code != http.StatusOK {
		t.Fatalf("plain query: %d %s", okRec.Code, okRec.Body.String())
	}

	s2, _, text2, _ := testService(t)
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodDelete, "http://"+host+"/mcp", nil)
		req.Host = host
		req.RemoteAddr = "127.0.0.1:9"
		req.Header.Set("Authorization", "Bearer 00")
		rec := httptest.NewRecorder()
		s2.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("delete %d: %d", i, rec.Code)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "http://"+host+"/mcp", strings.NewReader(init))
	req.Host = host
	req.RemoteAddr = "127.0.0.1:9"
	req.Header.Set("Authorization", "Bearer "+text2)
	rec := httptest.NewRecorder()
	s2.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("good token after DELETE failures: %d %s", rec.Code, rec.Body.String())
	}
	if *calls != 0 {
		t.Fatal("query-token request ran a tool")
	}
}

func TestLoopbackOriginRequiresTheAllowList(t *testing.T) {
	s, _, text, _ := testService(t)
	host := "127.0.0.1:4765"
	init := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"synthetic","version":"0"}}}`
	send := func(origin string) int {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "http://"+host+"/mcp", strings.NewReader(init))
		req.Host = host
		req.RemoteAddr = "127.0.0.1:9"
		req.Header.Set("Authorization", "Bearer "+text)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		return rec.Code
	}
	if send("http://127.0.0.1:4765") != http.StatusForbidden {
		t.Fatal("loopback origin was accepted from allowed_hosts")
	}
	if send("http://localhost:4765") != http.StatusForbidden {
		t.Fatal("localhost origin was accepted")
	}
	s.cfg.AllowedOrigins = []string{"http://127.0.0.1:4765"}
	if send("http://127.0.0.1:4765") != http.StatusOK {
		t.Fatal("listed loopback origin was rejected")
	}
	if send("http://localhost:4765") != http.StatusForbidden {
		t.Fatal("a different loopback origin was accepted")
	}
	if send("") != http.StatusOK {
		t.Fatal("a missing origin was rejected")
	}
}

func TestPerMinuteAndInFlightReturn429(t *testing.T) {
	s, _, text, _ := testService(t)
	host := "127.0.0.1:4765"
	s.cfg.MaxRequestsPerMinute = 1
	init := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"synthetic","version":"0"}}}`
	if post(s, text, host, "", init).Code != http.StatusOK {
		t.Fatal("first request failed")
	}
	if post(s, text, host, "", init).Code != http.StatusTooManyRequests {
		t.Fatal("per-minute cap did not return 429")
	}

	s2, _, text2, _ := testService(t)
	s2.cfg.RemoteTools = append(s2.cfg.RemoteTools, "mail_mark_read")
	release := make(chan struct{})
	started := make(chan struct{}, 2)
	s2.MCP.Register(mcp.Tool{
		Name:        "mail_mark_read",
		Description: "mark",
		InputSchema: []byte(`{"type":"object"}`),
		Handler: func(mcp.Context, json.RawMessage) (*mcp.ToolResult, error) {
			started <- struct{}{}
			<-release
			return mcp.StructuredResult(map[string]string{"ok": "yes"})
		},
	})
	sid := sessionOf(t, s2, text2, host)
	body := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"mail_mark_read","arguments":{}}}`
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			post(s2, text2, host, sid, body)
		}()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatal("slow handler did not start")
		}
	}
	if post(s2, text2, host, sid, body).Code != http.StatusTooManyRequests {
		t.Fatal("third in-flight request was not 429")
	}
	close(release)
	wg.Wait()
}

func TestSessionCapIdleAndRotate(t *testing.T) {
	s, _, text, _ := testService(t)
	host := "127.0.0.1:4765"
	now := time.Now()
	s.Now = func() time.Time { return now }
	var ids []string
	for i := 0; i < maxSessions+1; i++ {
		now = now.Add(time.Second)
		ids = append(ids, sessionOf(t, s, text, host))
	}
	if post(s, text, host, ids[0], `{"jsonrpc":"2.0","method":"notifications/initialized"}`).Code != http.StatusNotFound {
		t.Fatal("oldest session survived the cap")
	}
	if post(s, text, host, ids[len(ids)-1], `{"jsonrpc":"2.0","method":"notifications/initialized"}`).Code != http.StatusAccepted {
		t.Fatal("newest session was dropped")
	}
	now = now.Add(sessionIdle + time.Second)
	if post(s, text, host, ids[len(ids)-1], `{"jsonrpc":"2.0","method":"notifications/initialized"}`).Code != http.StatusNotFound {
		t.Fatal("idle session was still accepted")
	}

	s2, _, text2, _ := testService(t)
	cfg := httpconfig.Default()
	cfg.Enabled = true
	cfg.Listen = freeLoopback(t)
	if err := httpconfig.Save(s2.Path, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s2.Reload(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s2.Close)
	sid := sessionOf(t, s2, text2, host)
	next, err := keystore.GenerateHTTPToken()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { next.Zero() })
	s2.Token = func() (secret.Secret, error) { return next.Clone(), nil }
	if err := s2.Reload(); err != nil {
		t.Fatal(err)
	}
	fresh, err := keystore.EncodeHTTPToken(next.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if post(s2, fresh, host, sid, `{"jsonrpc":"2.0","method":"notifications/initialized"}`).Code != http.StatusNotFound {
		t.Fatal("rotate left the old session in place")
	}
}

func TestEnabledToDisabledClosesTheListener(t *testing.T) {
	s, _, _, _ := testService(t)
	cfg := httpconfig.Default()
	cfg.Enabled = true
	cfg.Listen = freeLoopback(t)
	if err := httpconfig.Save(s.Path, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	if !s.Listening() {
		t.Fatal("enabled config did not listen")
	}
	conn, err := net.Dial("tcp", s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()

	cfg.Enabled = false
	if err := httpconfig.Save(s.Path, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if s.Listening() {
		t.Fatal("disable left the listener up")
	}
	if _, err := net.DialTimeout("tcp", cfg.Listen, 200*time.Millisecond); err == nil {
		t.Fatal("dial succeeded after disable")
	}

	cfg.Enabled = true
	if err := httpconfig.Save(s.Path, cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.Path, []byte("enabled: true\nmax_unlock_hours: 99\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err == nil || s.Listening() {
		t.Fatalf("bad file err=%v listening=%v", err, s.Listening())
	}
}

func TestRequestLimitIsLongerThanTheHelperTimeout(t *testing.T) {
	if requestLimit != 45*time.Second {
		t.Fatalf("request limit = %s, want 45s", requestLimit)
	}
	if requestLimit <= 30*time.Second {
		t.Fatal("the HTTP request deadline is not longer than the helper timeout")
	}
}

func TestSafeErrorStripsAToken(t *testing.T) {
	raw := strings.Repeat("ab", 32)
	got := SafeError(fmt.Errorf("listen failed near %s", raw))
	if strings.Contains(got, raw) || !strings.Contains(got, "[redacted]") {
		t.Fatalf("safe error = %q", got)
	}
}

func TestNoticeRetriesWhenThePostFails(t *testing.T) {
	_, st, _, _ := testService(t)
	aw, err := audit.New(st.DB, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	id := aw.Begin(t.Context(), &audit.Entry{
		Caller:   caller.Caller{Transport: caller.TransportHTTP, Label: "remote"},
		Tool:     "mail_read",
		ArgsJSON: []byte(`{"message_id":"synthetic-message-1"}`),
	})
	aw.Complete(t.Context(), id, audit.OutcomeOK, "policy", "", time.Millisecond)
	y := time.Now().AddDate(0, 0, -1)
	if _, err := st.DB.Exec(`UPDATE audit_log SET ts = ? WHERE id = ?`, y.Unix(), id); err != nil {
		t.Fatal(err)
	}
	if err := DailyNotice(st.DB, time.Now(), func(string) error {
		return fmt.Errorf("osascript failed")
	}); err == nil {
		t.Fatal("a failed notification was treated as success")
	}
	var n int
	if err := st.DB.QueryRow(`SELECT COUNT(*) FROM http_notified`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("failed day was marked notified: %d", n)
	}
	var notes []string
	if err := DailyNotice(st.DB, time.Now(), func(text string) error {
		notes = append(notes, text)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(notes) != 1 {
		t.Fatalf("retry notes = %v", notes)
	}
}

func freeLoopback(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}
