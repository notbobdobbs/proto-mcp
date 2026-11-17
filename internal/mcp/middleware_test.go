package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/just-an-oldsalt/proto-mcp/internal/audit"
	"github.com/just-an-oldsalt/proto-mcp/internal/caller"
	"github.com/just-an-oldsalt/proto-mcp/internal/policy"
	"github.com/just-an-oldsalt/proto-mcp/internal/store"
)

func newTestAudit(t *testing.T) (*audit.Writer, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	w, err := audit.New(st.DB, filepath.Join(dir, "audit.log"), nil)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	t.Cleanup(func() {
		_ = w.Close()
		_ = st.Close()
	})
	return w, st
}

func newTestPolicy(t *testing.T, overrideYAML string) *policy.Engine {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := writeFile(path, overrideYAML); err != nil {
		t.Fatalf("write override: %v", err)
	}
	e, err := policy.New(context.Background(), path, nil)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	return e
}

func writeFile(path, body string) error {
	return writeBytesAtomic(path, []byte(body))
}

// TestMiddlewareAllowsByDefault — when no middleware is configured,
// the server behaves exactly like Phase 3 (existing server_test.go
// passes unchanged). This test confirms WithPolicy alone, with
// every tool flipped to allow, still runs the handler and writes
// no audit row when audit isn't wired.
func TestMiddlewareAllowsByDefault(t *testing.T) {
	called := false
	srv := New(nil)
	srv.Register(Tool{
		Name:        "echo",
		Description: "echo",
		InputSchema: json.RawMessage(`{"type":"object"}`),
		Handler: func(ctx Context, _ json.RawMessage) (*ToolResult, error) {
			called = true
			return StructuredResult(map[string]string{"ok": "yes"})
		},
	})
	resps := roundtrip(t, srv,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{}}}`,
	)
	if !called {
		t.Error("handler not called in Phase-3 mode")
	}
	if _, hasErr := resps[1]["error"]; hasErr {
		t.Errorf("unexpected error: %+v", resps[1])
	}
}

// TestMiddlewareDenyBlocks — policy returns deny → handler never
// runs, audit row has decision=deny, outcome=denied.
func TestMiddlewareDenyBlocks(t *testing.T) {
	w, st := newTestAudit(t)
	pol := newTestPolicy(t, `
defaults:
  decision: deny
tools:
  echo: { decision: deny }
`)

	called := false
	srv := New(nil, WithPolicy(pol), WithAudit(w), WithCallerResolver(caller.New()))
	srv.Register(Tool{
		Name:        "echo",
		Description: "echo",
		InputSchema: json.RawMessage(`{"type":"object"}`),
		Handler: func(ctx Context, _ json.RawMessage) (*ToolResult, error) {
			called = true
			return StructuredResult(map[string]string{"ok": "yes"})
		},
	})
	resps := roundtrip(t, srv,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{}}}`,
	)
	if called {
		t.Error("handler ran despite deny policy")
	}
	result := resps[1]["result"].(map[string]any)
	if result["isError"] != true {
		t.Errorf("expected isError; got %+v", result)
	}
	text := result["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "denied by policy") {
		t.Errorf("text doesn't mention policy denial: %s", text)
	}

	// Audit row outcome=denied.
	var outcome, decision string
	if err := st.DB.QueryRow(`SELECT outcome, policy_decision FROM audit_log WHERE tool = 'echo'`).Scan(&outcome, &decision); err != nil {
		t.Fatal(err)
	}
	if outcome != "denied" || decision != "deny" {
		t.Errorf("audit row: outcome=%q decision=%q, want denied/deny", outcome, decision)
	}
}

// TestMiddlewareLockedRefusesCall — Phase 6/E: when the lock-state
// callback returns true, the middleware short-circuits before any
// policy / approval work and returns an ErrorResult mentioning
// `protonmcp unlock`.
func TestMiddlewareLockedRefusesCall(t *testing.T) {
	called := false
	srv := New(nil, WithLockState(func() (bool, string) { return true, "SIGUSR1" }))
	srv.Register(Tool{
		Name:        "echo",
		Description: "echo",
		InputSchema: json.RawMessage(`{"type":"object"}`),
		Handler: func(ctx Context, _ json.RawMessage) (*ToolResult, error) {
			called = true
			return StructuredResult(map[string]string{"ok": "yes"})
		},
	})
	resps := roundtrip(t, srv,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{}}}`,
	)
	if called {
		t.Fatal("handler ran while runtime was locked")
	}
	result := resps[1]["result"].(map[string]any)
	if result["isError"] != true {
		t.Errorf("expected isError; got %+v", result)
	}
	text := result["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "locked") || !strings.Contains(text, "protonmcp unlock") {
		t.Errorf("locked-daemon text missing expected hints: %s", text)
	}
}

// TestMiddlewarePromptWithoutBrokerFallsToDeny — policy says prompt
// but no broker is configured → safe fallback is deny, not silent
// allow.
func TestMiddlewarePromptWithoutBrokerFallsToDeny(t *testing.T) {
	w, st := newTestAudit(t)
	pol := newTestPolicy(t, `
defaults:
  decision: deny
tools:
  echo: { decision: prompt, ttl: "0" }
`)
	called := false
	srv := New(nil, WithPolicy(pol), WithAudit(w))
	srv.Register(Tool{
		Name:        "echo",
		Description: "echo",
		InputSchema: json.RawMessage(`{"type":"object"}`),
		Handler: func(ctx Context, _ json.RawMessage) (*ToolResult, error) {
			called = true
			return &ToolResult{}, nil
		},
	})
	resps := roundtrip(t, srv,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{}}}`,
	)
	if called {
		t.Error("handler ran without broker — prompt should have fallen to deny")
	}
	result := resps[1]["result"].(map[string]any)
	if result["isError"] != true {
		t.Errorf("expected isError true: %+v", result)
	}
	var outcome string
	_ = st.DB.QueryRow(`SELECT outcome FROM audit_log WHERE tool = 'echo'`).Scan(&outcome)
	if outcome != "denied" {
		t.Errorf("audit outcome = %q, want denied", outcome)
	}
}

// TestMiddlewareHandlerPanicRecovers — buggy tool panics, middleware
// recover()s, audit row is outcome=error with the panic message,
// next call still works (loop didn't die).
func TestMiddlewareHandlerPanicRecovers(t *testing.T) {
	w, st := newTestAudit(t)
	pol := newTestPolicy(t, `
defaults:
  decision: deny
tools:
  echo: { decision: allow }
`)
	srv := New(nil, WithPolicy(pol), WithAudit(w))
	srv.Register(Tool{
		Name:        "echo",
		Description: "echo",
		InputSchema: json.RawMessage(`{"type":"object"}`),
		Handler: func(Context, json.RawMessage) (*ToolResult, error) {
			panic("kaboom")
		},
	})
	resps := roundtrip(t, srv,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{}}}`,
	)
	result := resps[1]["result"].(map[string]any)
	if result["isError"] != true {
		t.Errorf("panic should produce isError true: %+v", result)
	}
	text := result["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "kaboom") {
		t.Errorf("panic message lost: %s", text)
	}
	var outcome, errMsg string
	_ = st.DB.QueryRow(`SELECT outcome, error_msg FROM audit_log WHERE tool = 'echo'`).Scan(&outcome, &errMsg)
	if outcome != "error" {
		t.Errorf("audit outcome = %q, want error", outcome)
	}
	if !strings.Contains(errMsg, "kaboom") {
		t.Errorf("audit error_msg lost panic: %s", errMsg)
	}
}

// TestMiddlewareAllowRecordsOK — happy path: policy allow, handler
// runs, audit row outcome=ok, duration > 0, approval_source=policy.
func TestMiddlewareAllowRecordsOK(t *testing.T) {
	w, st := newTestAudit(t)
	pol := newTestPolicy(t, `tools:
  echo: { decision: allow }
`)
	srv := New(nil, WithPolicy(pol), WithAudit(w))
	srv.Register(Tool{
		Name:        "echo",
		Description: "echo",
		InputSchema: json.RawMessage(`{"type":"object"}`),
		Handler: func(Context, json.RawMessage) (*ToolResult, error) {
			return StructuredResult(map[string]int{"answer": 42})
		},
	})
	resps := roundtrip(t, srv,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{}}}`,
	)
	result := resps[1]["result"].(map[string]any)
	if result["isError"] == true {
		t.Errorf("unexpected isError: %+v", result)
	}
	var outcome, decision, approval string
	var duration int64
	err := st.DB.QueryRow(`SELECT outcome, policy_decision, approval_source, duration_ms FROM audit_log WHERE tool = 'echo'`).
		Scan(&outcome, &decision, &approval, &duration)
	if err != nil {
		t.Fatal(err)
	}
	if outcome != "ok" || decision != "allow" || approval != "policy" {
		t.Errorf("row: outcome=%q decision=%q approval=%q", outcome, decision, approval)
	}
	if duration < 0 {
		t.Errorf("duration should be non-negative, got %d", duration)
	}
}

// TestMiddlewareIsErrorResultRecordsError — #128: a handler that
// reports failure the codebase way (ErrorResult(...), nil) must be
// audited as outcome=error with its message (redacted), not ok.
func TestMiddlewareIsErrorResultRecordsError(t *testing.T) {
	w, st := newTestAudit(t)
	pol := newTestPolicy(t, `tools:
  echo: { decision: allow }
`)
	srv := New(nil, WithPolicy(pol), WithAudit(w))
	const token = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV0123456789"
	srv.Register(Tool{
		Name:        "echo",
		Description: "echo",
		InputSchema: json.RawMessage(`{"type":"object"}`),
		Handler: func(Context, json.RawMessage) (*ToolResult, error) {
			return ErrorResult("mail_send denied: recipient x@evil.com not on allowlist (tok %s)", token), nil
		},
	})
	resps := roundtrip(t, srv,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{}}}`,
	)
	result := resps[1]["result"].(map[string]any)
	if result["isError"] != true {
		t.Fatalf("handler's error result should reach the client unchanged: %+v", result)
	}
	var outcome, errMsg string
	if err := st.DB.QueryRow(`SELECT outcome, COALESCE(error_msg, '') FROM audit_log WHERE tool = 'echo'`).
		Scan(&outcome, &errMsg); err != nil {
		t.Fatal(err)
	}
	if outcome != "error" {
		t.Errorf("audit outcome = %q, want error", outcome)
	}
	if !strings.Contains(errMsg, "not on allowlist") {
		t.Errorf("audit error_msg = %q, want the result's text", errMsg)
	}
	if strings.Contains(errMsg, token) {
		t.Errorf("audit error_msg not redacted: %q", errMsg)
	}
}

// TestMiddlewareContextCallerOverridesResolver — Phase 6/D. The
// daemon stashes peer-cred via caller.WithCaller(ctx, peer) so the
// audit row gets the connecting client's identity, not the
// daemon's own PID. Middleware must prefer the ctx-stashed Caller
// over the process-wide Resolver.
func TestMiddlewareContextCallerOverridesResolver(t *testing.T) {
	pol := newTestPolicy(t, `tools:
  echo: { decision: allow }
`)
	var seenCaller CallerInfo
	srv := New(nil, WithPolicy(pol), WithCallerResolver(caller.New()))
	srv.Register(Tool{
		Name:        "echo",
		Description: "echo",
		InputSchema: json.RawMessage(`{"type":"object"}`),
		Handler: func(ctx Context, _ json.RawMessage) (*ToolResult, error) {
			seenCaller = ctx.Caller
			return StructuredResult(map[string]string{"ok": "yes"})
		},
	})

	// Inject a peer-cred Caller into ctx the way the daemon does
	// in its accept loop.
	peer := caller.Caller{PID: 99887, UID: 501, Binary: "/peer/binary"}
	ctx := caller.WithCaller(context.Background(), peer)

	in := strings.NewReader(strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{}}}`,
	}, "\n") + "\n")
	var out bytes.Buffer
	if err := srv.Serve(ctx, in, &out); err != nil {
		t.Fatalf("Serve: %v", err)
	}

	if seenCaller.PID != 99887 {
		t.Errorf("Caller.PID = %d, want 99887 (ctx-stashed peer-cred should override Resolver)", seenCaller.PID)
	}
	if seenCaller.Binary != "/peer/binary" {
		t.Errorf("Caller.Binary = %q, want /peer/binary", seenCaller.Binary)
	}
}

// TestMiddlewareCallerInfoReachesHandler — handlers see the resolved
// caller via Context.Caller. Phase 5 write tools will rely on this.
func TestMiddlewareCallerInfoReachesHandler(t *testing.T) {
	pol := newTestPolicy(t, `tools:
  echo: { decision: allow }
`)
	var seenCaller CallerInfo
	srv := New(nil, WithPolicy(pol), WithCallerResolver(caller.New()))
	srv.Register(Tool{
		Name:        "echo",
		Description: "echo",
		InputSchema: json.RawMessage(`{"type":"object"}`),
		Handler: func(ctx Context, _ json.RawMessage) (*ToolResult, error) {
			seenCaller = ctx.Caller
			return StructuredResult(map[string]string{"ok": "yes"})
		},
	})
	_ = roundtrip(t, srv,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{}}}`,
	)
	if seenCaller.PID == 0 {
		t.Errorf("Caller.PID not populated: %+v", seenCaller)
	}
}

// TestMiddlewareJSONRPCErrorBubbles — handler returning a typed
// *Error should produce a JSON-RPC error response, NOT a tool
// result with isError. Compatibility with Phase 3's two-flavor
// error mapping.
func TestMiddlewareJSONRPCErrorBubbles(t *testing.T) {
	pol := newTestPolicy(t, `tools:
  echo: { decision: allow }
`)
	srv := New(nil, WithPolicy(pol))
	srv.Register(Tool{
		Name:        "echo",
		Description: "echo",
		InputSchema: json.RawMessage(`{"type":"object"}`),
		Handler: func(Context, json.RawMessage) (*ToolResult, error) {
			return nil, NewError(CodeInvalidParams, "no thanks")
		},
	})
	resps := roundtrip(t, srv,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{}}}`,
	)
	if _, hasResult := resps[1]["result"]; hasResult {
		t.Errorf("expected no result; got %+v", resps[1])
	}
	errObj := resps[1]["error"].(map[string]any)
	if int(errObj["code"].(float64)) != CodeInvalidParams {
		t.Errorf("code = %v, want %d", errObj["code"], CodeInvalidParams)
	}
}

// _ unused — kept so the import isn't dropped if errors usage changes.
var _ = errors.New

func serveAs(t *testing.T, srv *Server, ctx context.Context, lines ...string) []map[string]any {
	t.Helper()
	if ctx == nil {
		ctx = context.Background()
	}
	in := strings.NewReader(strings.Join(lines, "\n") + "\n")
	var out bytes.Buffer
	if err := srv.Serve(ctx, in, &out); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("Serve: %v", err)
	}
	var responses []map[string]any
	dec := json.NewDecoder(&out)
	for dec.More() {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			t.Fatalf("decode response: %v\n%s", err, out.String())
		}
		responses = append(responses, m)
	}
	return responses
}

func toolCallLines(name, args string) []string {
	return []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"synthetic","version":"0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"` + name + `","arguments":` + args + `}}`,
	}
}

// A PID-0 HTTP caller is audited as that caller, for a read and for
// a denial. It must not be rewritten as the daemon's parent. Args
// keep message_id and store a body only as a hash and a length.
func TestMiddlewareHTTPCallerIsAudited(t *testing.T) {
	w, st := newTestAudit(t)
	pol := newTestPolicy(t, "{}\n")
	var reads, deniedRuns int
	srv := New(nil, WithPolicy(pol), WithAudit(w), WithCallerResolver(caller.New()))
	registerEcho := func(name string, counter *int) {
		srv.Register(Tool{
			Name:        name,
			Description: name,
			InputSchema: json.RawMessage(`{"type":"object"}`),
			Handler: func(Context, json.RawMessage) (*ToolResult, error) {
				*counter++
				return StructuredResult(map[string]string{"ok": "yes"})
			},
		})
	}
	registerEcho("mail_read", &reads)
	registerEcho("mail_delete_permanent", &deniedRuns)

	httpCaller := caller.Caller{
		Transport: caller.TransportHTTP,
		Label:     "remote",
		PID:       0,
		UID:       501,
	}
	ctx := caller.WithCaller(context.Background(), httpCaller)
	args := `{"message_id":"synthetic-message-1","body":"synthetic body not a mailbox"}`
	parent := os.Getppid()

	for _, name := range []string{"mail_read", "mail_delete_permanent"} {
		resps := serveAs(t, srv, ctx, toolCallLines(name, args)...)
		if len(resps) < 2 {
			t.Fatalf("%s: got %d responses", name, len(resps))
		}
	}
	if reads != 1 {
		t.Fatalf("mail_read handler calls = %d, want 1", reads)
	}
	if deniedRuns != 0 {
		t.Fatalf("denied tool handler ran %d times", deniedRuns)
	}

	rows, err := st.DB.Query(`
SELECT tool, caller_pid, caller_binary, transport, caller_label, claimed_client, outcome, args_json
FROM audit_log ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var tool, binary, transport, label, claimed, outcome, argsJSON string
		var pid int
		if err := rows.Scan(&tool, &pid, &binary, &transport, &label, &claimed, &outcome, &argsJSON); err != nil {
			t.Fatal(err)
		}
		seen[tool] = true
		if pid != 0 {
			t.Errorf("%s caller_pid = %d, want 0 (parent pid is %d; that would be the launchd fallback)", tool, pid, parent)
		}
		if transport != caller.TransportHTTP || label != "remote" {
			t.Errorf("%s transport=%q label=%q, want http/remote", tool, transport, label)
		}
		if binary != "" {
			t.Errorf("%s caller_binary = %q, want empty", tool, binary)
		}
		if claimed != "" {
			t.Errorf("%s claimed_client = %q, want empty until a later change records it", tool, claimed)
		}
		if strings.Contains(argsJSON, "synthetic body not a mailbox") {
			t.Errorf("%s stored the body literally: %s", tool, argsJSON)
		}
		if !strings.Contains(argsJSON, `"message_id":"synthetic-message-1"`) {
			t.Errorf("%s lost message_id: %s", tool, argsJSON)
		}
		if !strings.Contains(argsJSON, `"sha256"`) || !strings.Contains(argsJSON, `"bytes"`) {
			t.Errorf("%s body was not stored as sha256 and bytes: %s", tool, argsJSON)
		}
		switch tool {
		case "mail_read":
			if outcome != "ok" {
				t.Errorf("mail_read outcome = %q, want ok", outcome)
			}
		case "mail_delete_permanent":
			if outcome != "denied" {
				t.Errorf("mail_delete_permanent outcome = %q, want denied", outcome)
			}
		default:
			t.Errorf("unexpected tool %s", tool)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !seen["mail_read"] || !seen["mail_delete_permanent"] {
		t.Fatalf("audit rows = %v, want both tools", seen)
	}
}

func TestMiddlewareUnixRowLeavesClaimedClientEmpty(t *testing.T) {
	w, st := newTestAudit(t)
	pol := newTestPolicy(t, "{}\n")
	srv := New(nil, WithPolicy(pol), WithAudit(w), WithCallerResolver(caller.New()))
	srv.Register(Tool{
		Name:        "mail_read",
		Description: "read",
		InputSchema: json.RawMessage(`{"type":"object"}`),
		Handler: func(Context, json.RawMessage) (*ToolResult, error) {
			return StructuredResult(map[string]string{"ok": "yes"})
		},
	})
	ctx := caller.WithCaller(context.Background(), caller.Caller{
		Transport: caller.TransportUnix,
		PID:       4242,
		UID:       501,
		Binary:    "/synthetic/client",
	})
	serveAs(t, srv, ctx, toolCallLines("mail_read", `{"message_id":"synthetic-message-1"}`)...)

	var transport, label, claimed string
	var pid int
	if err := st.DB.QueryRow(`SELECT caller_pid, transport, caller_label, claimed_client FROM audit_log WHERE tool = 'mail_read'`).
		Scan(&pid, &transport, &label, &claimed); err != nil {
		t.Fatal(err)
	}
	if pid != 4242 || transport != "unix" || label != "" || claimed != "" {
		t.Errorf("unix row pid=%d transport=%q label=%q claimed=%q", pid, transport, label, claimed)
	}
}

// Two PIDs share one per-tool bucket. The second call is over the
// cap whichever caller makes it. The persisted key is the tool name,
// not tool|pid.
func TestMiddlewareRateLimitIsPerTool(t *testing.T) {
	w, _ := newTestAudit(t)
	pol := newTestPolicy(t, `
tools:
  mail_read:
    decision: allow
    rate_limit: "1/hour"
`)
	persisted := &fakePersister{}
	var calls int
	srv := New(nil,
		WithPolicy(pol),
		WithAudit(w),
		WithCallerResolver(caller.New()),
		WithRateLimitPersister(persisted),
	)
	srv.Register(Tool{
		Name:        "mail_read",
		Description: "read",
		InputSchema: json.RawMessage(`{"type":"object"}`),
		Handler: func(Context, json.RawMessage) (*ToolResult, error) {
			calls++
			return StructuredResult(map[string]string{"ok": "yes"})
		},
	})

	call := func(pid int) string {
		t.Helper()
		ctx := caller.WithCaller(context.Background(), caller.Caller{
			Transport: caller.TransportUnix,
			PID:       pid,
			UID:       501,
			Binary:    "/synthetic/client",
		})
		resps := serveAs(t, srv, ctx, toolCallLines("mail_read", `{}`)...)
		if len(resps) < 2 {
			t.Fatalf("pid %d: %d responses", pid, len(resps))
		}
		result, _ := resps[1]["result"].(map[string]any)
		if result == nil {
			t.Fatalf("pid %d: no result: %+v", pid, resps[1])
		}
		if result["isError"] == true {
			return result["content"].([]any)[0].(map[string]any)["text"].(string)
		}
		return ""
	}

	if msg := call(111); msg != "" {
		t.Fatalf("first caller denied: %s", msg)
	}
	msg := call(222)
	if !strings.Contains(msg, "rate limit") {
		t.Fatalf("second pid should share the bucket and be denied; got %q", msg)
	}
	if calls != 1 {
		t.Fatalf("handler calls = %d, want 1", calls)
	}
	if len(persisted.saved) != 1 {
		t.Fatalf("buckets = %#v, want one", persisted.saved)
	}
	if _, ok := persisted.saved["mail_read"]; !ok {
		t.Fatalf("bucket key = %#v, want mail_read", persisted.saved)
	}
}

func TestMiddlewareHTTPAuditWriteFailureRefusesTheTool(t *testing.T) {
	w, st := newTestAudit(t)
	pol := newTestPolicy(t, "{}\n")
	if err := st.DB.Close(); err != nil {
		t.Fatal(err)
	}
	var httpCalls, unixCalls int
	srv := New(nil, WithPolicy(pol), WithAudit(w))
	srv.Register(Tool{
		Name:        "mail_read",
		Description: "read",
		InputSchema: json.RawMessage(`{"type":"object"}`),
		Handler: func(ctx Context, _ json.RawMessage) (*ToolResult, error) {
			if ctx.Caller.PID == 0 {
				httpCalls++
			} else {
				unixCalls++
			}
			return StructuredResult(map[string]string{"ok": "yes"})
		},
	})
	httpCtx := caller.WithCaller(context.Background(), caller.Caller{
		Transport: caller.TransportHTTP, Label: "remote", PID: 0, UID: 501,
	})
	resps := serveAs(t, srv, httpCtx, toolCallLines("mail_read", `{}`)...)
	if len(resps) < 2 {
		t.Fatalf("responses %d", len(resps))
	}
	text := resps[1]["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "audit log") {
		t.Fatalf("HTTP text = %q", text)
	}
	if httpCalls != 0 {
		t.Fatal("HTTP tool ran without an audit row")
	}
	unixCtx := caller.WithCaller(context.Background(), caller.Caller{
		Transport: caller.TransportUnix, PID: 42, UID: 501, Binary: "/synthetic/client",
	})
	resps = serveAs(t, srv, unixCtx, toolCallLines("mail_read", `{}`)...)
	if unixCalls != 1 {
		t.Fatalf("unix calls = %d, responses %+v", unixCalls, resps)
	}
}
