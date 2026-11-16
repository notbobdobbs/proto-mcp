package httpmcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/just-an-oldsalt/proto-mcp/internal/approval"
	"github.com/just-an-oldsalt/proto-mcp/internal/audit"
	"github.com/just-an-oldsalt/proto-mcp/internal/caller"
	"github.com/just-an-oldsalt/proto-mcp/internal/httpconfig"
	"github.com/just-an-oldsalt/proto-mcp/internal/keystore"
	"github.com/just-an-oldsalt/proto-mcp/internal/mcp"
	"github.com/just-an-oldsalt/proto-mcp/internal/policy"
	"github.com/just-an-oldsalt/proto-mcp/internal/secret"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

func testToken(t *testing.T) (string, TokenFunc) {
	t.Helper()
	tok, err := keystore.GenerateHTTPToken()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tok.Zero() })
	text, err := keystore.EncodeHTTPToken(tok.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return text, func() (secret.Secret, error) { return tok.Clone(), nil }
}

func testService(t *testing.T) (*Service, *store.Store, string, *int) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "store.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	aw, err := audit.New(st.DB, filepath.Join(dir, "audit.log"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = aw.Close() })
	pol, err := policy.New(t.Context(), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	var calls int
	srv := mcp.New(nil, mcp.WithPolicy(pol), mcp.WithAudit(aw))
	srv.Register(mcp.Tool{
		Name:        "mail_read",
		Description: "read",
		InputSchema: []byte(`{"type":"object"}`),
		Handler: func(mcp.Context, json.RawMessage) (*mcp.ToolResult, error) {
			calls++
			return mcp.StructuredResult(map[string]string{"ok": "yes"})
		},
	})
	text, token := testToken(t)
	s := New(srv, filepath.Join(dir, "http.yaml"), token)
	s.cfg = httpconfig.Default()
	s.cfg.CallerLabel = "remote"
	srv.UseRemoteAllow(s.Allows)
	s.Reads = NewReadCap(st.DB, func() time.Time { return time.Now() }, func() int { return 2 })
	srv.UseReadCap(s.Reads.Take)
	return s, st, text, &calls
}

func post(s *Service, token, host, session, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "http://"+host+"/mcp", strings.NewReader(body))
	req.Host = host
	req.RemoteAddr = "127.0.0.1:9"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if session != "" {
		req.Header.Set("Mcp-Session-Id", session)
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

func TestListenRejectsNonLoopback(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:4765", "192.168.1.9:4765", ":4765", "localhost:4765", "example.com:4765"} {
		if err := ValidateAddr(addr); err == nil {
			t.Errorf("ValidateAddr(%s) succeeded", addr)
		}
	}
	ln, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = ln.Close()
	if !LoopbackRemote("127.0.0.1:9") || LoopbackRemote("192.0.2.1:9") {
		t.Fatal("loopback check is wrong")
	}
}

func TestDisabledOrTokenlessDoesNotListen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "http.yaml")
	cfg := httpconfig.Default()
	cfg.Listen = "127.0.0.1:0"
	if err := httpconfig.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	_, token := testToken(t)
	s := New(mcp.New(nil), path, token)
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if s.Listening() {
		t.Fatal("disabled config opened a port")
	}
	cfg.Enabled = true
	if err := httpconfig.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	s.Token = func() (secret.Secret, error) { return secret.Secret{}, keystore.ErrHTTPTokenNotFound }
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if s.Listening() {
		t.Fatal("missing token opened a port")
	}
}

func TestAuthRejectsBeforeTheTool(t *testing.T) {
	s, _, text, calls := testService(t)
	host := "127.0.0.1:4765"
	init := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"synthetic","version":"0"}}}`
	for _, tok := range []string{"", "abcd", text[:8] + "00"} {
		rec := post(s, tok, host, "", init)
		if rec.Code != http.StatusUnauthorized || rec.Body.Len() != 0 {
			t.Fatalf("token %q: code %d body %q", tok, rec.Code, rec.Body.String())
		}
	}
	req := httptest.NewRequest(http.MethodPost, "http://"+host+"/mcp?token="+text, strings.NewReader(init))
	req.Host = host
	req.RemoteAddr = "127.0.0.1:9"
	req.Header.Set("Authorization", "Bearer "+text)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || rec.Body.Len() != 0 {
		t.Fatalf("query token: code %d body %q", rec.Code, rec.Body.String())
	}
	if *calls != 0 {
		t.Fatal("tool ran without auth")
	}
}

func TestProtocolHostOriginAndMethods(t *testing.T) {
	s, _, text, _ := testService(t)
	host := "127.0.0.1:4765"
	init := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"synthetic","version":"0"}}}`

	get := httptest.NewRequest(http.MethodGet, "http://"+host+"/mcp", nil)
	get.Host = host
	get.RemoteAddr = "127.0.0.1:9"
	grec := httptest.NewRecorder()
	s.ServeHTTP(grec, get)
	if grec.Code != http.StatusMethodNotAllowed || grec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("GET %d cors %q", grec.Code, grec.Header().Get("Access-Control-Allow-Origin"))
	}
	opt := httptest.NewRequest(http.MethodOptions, "http://"+host+"/mcp", nil)
	opt.Host = host
	opt.RemoteAddr = "127.0.0.1:9"
	orec := httptest.NewRecorder()
	s.ServeHTTP(orec, opt)
	if orec.Code != http.StatusMethodNotAllowed || orec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("OPTIONS %d", orec.Code)
	}

	bad := post(s, text, host, "", init)
	// good host, then override protocol on a copy
	req := httptest.NewRequest(http.MethodPost, "http://"+host+"/mcp", strings.NewReader(init))
	req.Host = host
	req.RemoteAddr = "127.0.0.1:9"
	req.Header.Set("Authorization", "Bearer "+text)
	req.Header.Set("MCP-Protocol-Version", "1999-01-01")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad protocol %d", rec.Code)
	}
	_ = bad

	req = httptest.NewRequest(http.MethodPost, "http://evil.example/mcp", strings.NewReader(init))
	req.Host = "evil.example"
	req.RemoteAddr = "127.0.0.1:9"
	req.Header.Set("Authorization", "Bearer "+text)
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("bad host %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodPost, "http://"+host+"/mcp", strings.NewReader(init))
	req.Host = host
	req.RemoteAddr = "127.0.0.1:9"
	req.Header.Set("Authorization", "Bearer "+text)
	req.Header.Set("Origin", "null")
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("null origin %d", rec.Code)
	}
	req.Header.Set("Origin", "https://evil.example")
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("bad origin %d", rec.Code)
	}

	off := httptest.NewRequest(http.MethodPost, "http://"+host+"/mcp", strings.NewReader(init))
	off.Host = host
	off.RemoteAddr = "192.0.2.1:9"
	off.Header.Set("Authorization", "Bearer "+text)
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, off)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-loopback %d", rec.Code)
	}
}

func TestInitializeSessionAndAudit(t *testing.T) {
	s, st, text, calls := testService(t)
	host := "127.0.0.1:4765"
	body := `{"message_id":"synthetic-message-1","body":"synthetic body not a mailbox"}`
	init := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"synthetic","version":"0"}}}`
	rec := post(s, text, host, "", init)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"protocolVersion":"2025-06-18"`) {
		t.Fatalf("initialize %d %s", rec.Code, rec.Body.String())
	}
	sid := rec.Header().Get("Mcp-Session-Id")
	if len(sid) < 32 {
		t.Fatalf("session id %q", sid)
	}
	early := post(s, text, host, sid, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"mail_read","arguments":`+body+`}}`)
	if !strings.Contains(early.Body.String(), "not initialized") {
		t.Fatalf("early call %s", early.Body.String())
	}
	note := post(s, text, host, sid, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if note.Code != http.StatusAccepted {
		t.Fatalf("initialized %d", note.Code)
	}
	req := httptest.NewRequest(http.MethodPost, "http://"+host+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"mail_read","arguments":`+body+`}}`))
	req.Host = host
	req.RemoteAddr = "127.0.0.1:9"
	req.Header.Set("Authorization", "Bearer "+text)
	req.Header.Set("Mcp-Session-Id", sid)
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if *calls != 1 {
		t.Fatalf("handler calls %d body %s", *calls, rec.Body.String())
	}
	var transport, label, claimed, args string
	if err := st.DB.QueryRow(`SELECT transport, caller_label, claimed_client, args_json FROM audit_log WHERE tool = 'mail_read' AND outcome = 'ok'`).
		Scan(&transport, &label, &claimed, &args); err != nil {
		t.Fatal(err)
	}
	if transport != "http" || label != "remote" || claimed != "synthetic" {
		t.Fatalf("audit transport=%s label=%s claimed=%s", transport, label, claimed)
	}
	if strings.Contains(args, "synthetic body not a mailbox") || !strings.Contains(args, `"message_id":"synthetic-message-1"`) || !strings.Contains(args, `"sha256"`) {
		t.Fatalf("args redaction %s", args)
	}
}

func TestRemoteDenyDoesNotPrompt(t *testing.T) {
	s, st, text, _ := testService(t)
	helper := filepath.Join(t.TempDir(), "fake-touchid")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\necho prompted >> '"+helper+".log'\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PROTONMCP_TOUCHID", helper)
	broker, err := approval.New(helper, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.MCP.UseApproval(broker)
	host := "127.0.0.1:4765"
	sid := sessionOf(t, s, text, host)
	// mail_draft_delete is prompt in policy and off the default remote list.
	s.MCP.Register(mcp.Tool{
		Name:        "mail_draft_delete",
		Description: "no",
		InputSchema: []byte(`{"type":"object"}`),
		Handler: func(mcp.Context, json.RawMessage) (*mcp.ToolResult, error) {
			t.Fatal("remote draft delete handler ran")
			return nil, nil
		},
	})
	rec := post(s, text, host, sid, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"mail_draft_delete","arguments":{"draft_id":"synthetic-1"}}}`)
	if !strings.Contains(rec.Body.String(), "not available") {
		t.Fatalf("draft delete %s", rec.Body.String())
	}
	if _, err := os.Stat(helper + ".log"); err == nil {
		t.Fatal("allowlist denial started the helper")
	}
	var outcome string
	if err := st.DB.QueryRow(`SELECT outcome FROM audit_log WHERE tool = 'mail_draft_delete'`).Scan(&outcome); err != nil {
		t.Fatal(err)
	}
	if outcome != "denied" {
		t.Fatalf("outcome %s", outcome)
	}
}

func TestAuthFailureLockout(t *testing.T) {
	// The failure bucket is shared by every caller, on purpose: a
	// scanner and the real bot arrive from the same loopback address.
	s, _, text, calls := testService(t)
	host := "127.0.0.1:4765"
	init := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	for i := 0; i < 11; i++ {
		post(s, "00", host, "", init)
	}
	rec := post(s, text, host, "", init)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("good token after lockout: %d %s", rec.Code, rec.Body.String())
	}
	if *calls != 0 {
		t.Fatal("tool ran during lockout")
	}
}

func TestDailyReadCapSurvivesRestart(t *testing.T) {
	s, st, text, calls := testService(t)
	host := "127.0.0.1:4765"
	sid := sessionOf(t, s, text, host)
	call := `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"mail_read","arguments":{"message_id":"synthetic-message-1"}}}`
	for i := 0; i < 2; i++ {
		rec := post(s, text, host, sid, call)
		if strings.Contains(rec.Body.String(), "isError") && strings.Contains(rec.Body.String(), "cap") {
			t.Fatalf("call %d denied early: %s", i, rec.Body.String())
		}
	}
	rec := post(s, text, host, sid, call)
	if !strings.Contains(rec.Body.String(), "cap") {
		t.Fatalf("over-cap call ran: %s", rec.Body.String())
	}
	// A new counter on the same database still sees the day.
	again := NewReadCap(st.DB, func() time.Time { return time.Now() }, func() int { return 2 })
	if err := again.Take("mail_read"); err == nil {
		t.Fatal("restart zeroed the daily cap")
	}
	if *calls != 2 {
		t.Fatalf("handler calls %d, want 2", *calls)
	}
}

func TestUnlockClockDoesNotMoveOnReads(t *testing.T) {
	start := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	now := start
	clock := NewUnlockClock(func() time.Time { return now })
	clock.Stamp(start)
	var prompts int
	prompt := func(context.Context) error {
		prompts++
		return nil
	}
	for i := 0; i < 5; i++ {
		now = start.Add(time.Duration(i) * time.Minute)
		if err := clock.Gate(t.Context(), 8, prompt); err != nil {
			t.Fatal(err)
		}
	}
	if prompts != 0 {
		t.Fatal("reads prompted before the window")
	}
	if clock.Age(start.Add(time.Minute)) > 2*time.Minute {
		t.Fatal("a read moved the stamp")
	}
	now = start.Add(8*time.Hour + time.Minute)
	if err := clock.Gate(t.Context(), 8, prompt); err != nil {
		t.Fatal(err)
	}
	if prompts != 1 {
		t.Fatalf("prompts %d, want 1", prompts)
	}
	prompts = 0
	fail := func(context.Context) error { return errCooldown }
	// Stamp was reset by the success above, so move past it again.
	now = now.Add(8*time.Hour + time.Minute)
	if err := clock.Gate(t.Context(), 8, fail); err == nil {
		t.Fatal("decline was treated as success")
	}
	aged := clock.Age(now)
	if aged < 8*time.Hour {
		t.Fatal("decline reset the stamp")
	}
}

func TestActivityAndNoticeOmitBodies(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "store.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	aw, err := audit.New(st.DB, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"message_id":"synthetic-message-1","body":"synthetic body not a mailbox"}`
	id := aw.Begin(t.Context(), &audit.Entry{
		Caller:        caller.Caller{Transport: caller.TransportHTTP, Label: "remote"},
		Tool:          "mail_read",
		ArgsJSON:      []byte(body),
		ClaimedClient: "synthetic",
	})
	aw.Complete(t.Context(), id, audit.OutcomeOK, "policy", "", time.Millisecond)
	// Plant the body marker in the row the way a bad writer might.
	if _, err := st.DB.Exec(`UPDATE audit_log SET args_json = ? WHERE id = ?`, body, id); err != nil {
		t.Fatal(err)
	}
	text, err := ActivityText(st.DB, time.Now(), false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(text, "synthetic body not a mailbox") || strings.Contains(text, "synthetic-message-1") {
		t.Fatalf("activity leaked args: %s", text)
	}
	if !strings.Contains(text, "mail_read") || !strings.Contains(text, "ok") {
		t.Fatalf("activity %s", text)
	}
	withIDs, err := ActivityText(st.DB, time.Now(), true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(withIDs, "synthetic-message-1") || strings.Contains(withIDs, "synthetic body not a mailbox") {
		t.Fatalf("ids report %s", withIDs)
	}

	var notes []string
	// The row is today, so yesterday is empty and must not notify.
	if err := DailyNotice(st.DB, time.Now(), func(s string) error {
		notes = append(notes, s)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(notes) != 0 {
		t.Fatalf("notified for an empty completed day: %v", notes)
	}
	// Move the row to yesterday and notify once.
	y := time.Now().AddDate(0, 0, -1)
	if _, err := st.DB.Exec(`UPDATE audit_log SET ts = ? WHERE id = ?`, y.Unix(), id); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB.Exec(`DELETE FROM http_notified`); err != nil {
		t.Fatal(err)
	}
	if err := DailyNotice(st.DB, time.Now(), func(s string) error {
		notes = append(notes, s)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(notes) != 1 || strings.Contains(notes[0], "synthetic body") || !strings.Contains(notes[0], "total") {
		t.Fatalf("notice %v", notes)
	}
	if err := DailyNotice(st.DB, time.Now(), func(s string) error {
		notes = append(notes, s)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(notes) != 1 {
		t.Fatalf("notified twice: %v", notes)
	}
}

func TestOnlyThisPackageListensTCP(t *testing.T) {
	root := filepath.Join("..", "..")
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.HasSuffix(path, "httpmcp/listen.go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(b), "\n") {
			trim := strings.TrimSpace(line)
			if strings.HasPrefix(trim, "//") {
				continue
			}
			if strings.Contains(line, `net.Listen("tcp"`) || strings.Contains(line, "net.ListenTCP(") {
				t.Errorf("TCP listen outside the loopback wrapper: %s", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestBodyOverCapIs413(t *testing.T) {
	s, _, text, calls := testService(t)
	host := "127.0.0.1:4765"
	req := httptest.NewRequest(http.MethodPost, "http://"+host+"/mcp", strings.NewReader("x"))
	req.Host = host
	req.RemoteAddr = "127.0.0.1:9"
	req.Header.Set("Authorization", "Bearer "+text)
	req.ContentLength = bodyCap + 1
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("code %d", rec.Code)
	}
	if *calls != 0 {
		t.Fatal("oversized body dispatched")
	}
}

func TestDialogNamesTheHTTPCaller(t *testing.T) {
	s, _, text, _ := testService(t)
	out := filepath.Join(t.TempDir(), "payload.json")
	helper := filepath.Join(t.TempDir(), "fake-touchid")
	script := "#!/bin/sh\ncat > '" + out + "'\nexit 0\n"
	if err := os.WriteFile(helper, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	broker, err := approval.New(helper, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.MCP.UseApproval(broker)
	s.MCP.Register(mcp.Tool{
		Name:        "mail_trash",
		Description: "trash",
		InputSchema: []byte(`{"type":"object"}`),
		Handler: func(mcp.Context, json.RawMessage) (*mcp.ToolResult, error) {
			return mcp.StructuredResult(map[string]string{"ok": "yes"})
		},
	})
	host := "127.0.0.1:4765"
	sid := sessionOf(t, s, text, host)
	post(s, text, host, sid, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"mail_trash","arguments":{"message_id":"synthetic-message-1"}}}`)
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Caller  string `json:"caller"`
		Confirm bool   `json:"confirm"`
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("payload %s: %v", data, err)
	}
	if got.Caller != "http:remote" {
		t.Fatalf("dialog caller = %q, want http:remote (%s)", got.Caller, data)
	}
}

func TestHTTPTrashAlreadyInTrashDoesNotRun(t *testing.T) {
	s, st, text, _ := testService(t)
	if err := st.UpsertMessage(t.Context(), store.Message{
		ID: "synthetic-message-1", ThreadID: "t", Folder: "trash", Date: time.Unix(1, 0),
	}); err != nil {
		t.Fatal(err)
	}
	var ran int
	s.MCP.UseTrashGuard(func(ctx context.Context, args json.RawMessage) error {
		return TrashRefused(ctx, st, args)
	})
	s.MCP.Register(mcp.Tool{
		Name:        "mail_trash",
		Description: "trash",
		InputSchema: []byte(`{"type":"object"}`),
		Handler: func(mcp.Context, json.RawMessage) (*mcp.ToolResult, error) {
			ran++
			return mcp.StructuredResult(map[string]string{"ok": "yes"})
		},
	})
	host := "127.0.0.1:4765"
	sid := sessionOf(t, s, text, host)
	rec := post(s, text, host, sid, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"mail_trash","arguments":{"message_id":"synthetic-message-1"}}}`)
	if ran != 0 || !strings.Contains(rec.Body.String(), "already in Trash") {
		t.Fatalf("ran %d body %s", ran, rec.Body.String())
	}
}

func sessionOf(t *testing.T, s *Service, text, host string) string {
	t.Helper()
	init := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"synthetic","version":"0"}}}`
	rec := post(s, text, host, "", init)
	sid := rec.Header().Get("Mcp-Session-Id")
	if sid == "" {
		t.Fatalf("no session: %d %s", rec.Code, rec.Body.String())
	}
	post(s, text, host, sid, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	return sid
}
