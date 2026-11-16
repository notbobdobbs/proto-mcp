# Remote MCP for Grok Bot

Plan only. This file does not enable anything. The daemon stays a
local Unix-socket server until the later changes below are written
and you turn them on.

The approved goal (16 Nov 2026): Grok Bot, and your other bots, can
search, read, file, draft, and send Proton mail through proto-mcp on
your Mac. Grok Bot can only connect to a remote HTTPS MCP endpoint.
It cannot open the Unix socket, and nothing in this plan runs on
Grok Bot's computer.

## 1. For the owner

Today the mail bridge only talks to programs on your Mac, through a
private socket. Grok Bot lives somewhere else, so it cannot use that
socket.

The change adds a second door on the same daemon. The door listens
only on the Mac itself. A private encrypted tunnel forwards one
public HTTPS address to that door. The door is locked with a long
random password (a bearer token) kept in the macOS Keychain. It is
off until you turn it on.

Reading mail still does not ask for Touch ID. Anyone who holds the
token can read mail while the Mac is awake, online, and the daemon
is unlocked. Sending, filing, and deleting still stop for the same
approval prompt on the Mac screen, and the prompt names the real
recipients. A remote caller cannot skip that prompt, pre-approve it,
or loosen the rules. If you walk away, the daemon still locks. If
you do not approve in time, nothing is sent.

Two costs you already accepted: mail text a bot reads passes through
Grok Bot's servers, and this only works while the Mac is awake and
online. The tunnel we recommend does not let the tunnel company read
that mail. Turning the tunnel off, or revoking the token, closes the
door.

## 2. Design

### Constraints

- macOS daemon only. `protonmcp serve-stdio` does not grow a network
  listener.
- Off unless both switches are on: `http.yaml` has `enabled: true`,
  and the Keychain holds a token. Missing either one means no
  listener.
- The Unix socket stays
  `~/Library/Application Support/protonmcp/protonmcp.sock`, mode
  `0600`, in the existing `0700` directory. Peer-credential checks
  stay as they are.
- One shared tool pipeline. HTTP calls `(*mcp.Server).dispatch` and
  then the same middleware as a socket client (`internal/mcp/server.go`,
  `internal/mcp/middleware.go`). No second policy engine, no second
  approval path.
- Remote requests cannot change `decision`, `confirm`, `ttl`,
  `allowed_recipients`, or `rate_limit`. `policy.Engine.Decide`
  keeps ignoring caller identity for the decision. There is no tool
  that edits policy.
- The advertised MCP version stays the existing constant
  `ProtocolVersion` (`2025-06-18` in `internal/mcp/types.go`).
- No OAuth, no second token, no code on Grok Bot's computer, no
  Proton protocol changes. The tunnel is something you run; it is
  not a proto-mcp feature.
- Secrets never go in git, logs, audit rows, or process arguments.

### Transport

Add a Streamable HTTP endpoint on the daemon, the shape remote MCP
clients already speak (protocol revisions 2025-03-26 and 2025-06-18).

- Bind only a literal loopback address. Default
  `127.0.0.1:4765`. Also allowed: `::1` with an explicit port.
  Refuse `0.0.0.0`, empty host, a LAN address, and the hostname
  `localhost` (no DNS). A wrapper, not a raw `net.Listen`, is the
  only TCP listen in the repo. `MustNotListenTCP` in
  `internal/mcp/trustguard.go` still panics for every other
  package. The old "no TCP at all" comment is updated to "TCP only
  via this loopback wrapper."
- Path `/mcp`. POST carries one JSON-RPC message and returns one
  JSON object (`Content-Type: application/json`). The daemon does
  not push unsolicited messages, so GET returns `405`. There is no
  CORS header and OPTIONS returns `405`.
- On `initialize`, mint an in-memory session id (32 random bytes,
  encoded for the `Mcp-Session-Id` header). Remember at most 8
  sessions, each dropped after 15 minutes idle, and drop them all
  when the token rotates or disappears. Every later request still
  presents the bearer token; the session id is not a second
  password. `tools/call` before `notifications/initialized` on that
  session still returns "server not initialized", matching
  `dispatch`. DELETE with a valid session drops it. A client that
  sends `MCP-Protocol-Version` other than `2025-06-18` or
  `2025-03-26` gets HTTP 400 and no tool call.
- Body cap is 8 MiB, the same ceiling as the NDJSON scanner in
  `(*mcp.Server).Serve`. Over that, HTTP 413, no dispatch.
- `RemoteAddr` must be loopback. Ignore `X-Forwarded-For` and any
  client-supplied identity.

Config lives in its own file, not in `policy.yaml`, so editing tool
rules cannot open the port:

```yaml
# ~/Library/Application Support/protonmcp/http.yaml
# mode 0600. Absent file means off.
enabled: false
listen: 127.0.0.1:4765
caller_label: remote          # what the audit log and the approval dialog call this caller
allowed_hosts:                # Host header, no scheme, port optional
  - 127.0.0.1:4765
  - localhost:4765
max_requests_per_minute: 60   # authenticated calls; 0 means this default, never unlimited
```

You add the tunnel's public hostname to `allowed_hosts` when you
turn the tunnel on. A Host or Origin that is not on the list is
rejected (`403`) before any tool runs. A missing Origin is allowed,
because non-browser MCP clients do not send one. A present Origin
must match an entry you listed. The value `null` is rejected. The
default list has no Origins, so a browser is refused.

`protonmcp policy reload` (SIGHUP) also re-reads `http.yaml` and
opens or closes the listener. The token is not cached: each request
reads it from the Keychain, so revoke is immediate.

### Auth

One token. 32 bytes from `crypto/rand`, stored as a Keychain generic
password next to the existing items, not inside them:

| | Service | Account | Label |
|---|---|---|---|
| Proton session (existing) | `zone.dort.protonmcp` | `session` | Proton MCP session |
| Mirror key (existing) | `zone.dort.protonmcp` | `store-key` | Proton MCP mailbox mirror |
| Remote token (new) | `zone.dort.protonmcp` | `http-bearer` | Proton MCP remote token |

Same item flags as the mirror key: `AccessibleWhenUnlocked`, not
iCloud-synced. `keystore.Delete` keeps deleting only the `session`
account, so `protonmcp logout` does not remove the token or the
mirror key.

The client sends `Authorization: Bearer <token>` on every request,
including `initialize`. The token is never accepted in the query
string; a request that puts it there is `401` and the query is not
logged. Compare the raw 32 bytes with
`crypto/subtle.ConstantTimeCompare`. A wrong length fails closed
without comparing the secret against attacker-controlled bytes of a
different length. Wrong, missing, or unreadable Keychain state is
HTTP `401` with an empty body. That path does not start a session,
does not raise Touch ID, does not bump the idle timer, and does not
write a tool audit row.

Commands, all local:

- `protonmcp http enable` / `http disable` — write `enabled` and
  signal the daemon. Enable refuses to start the listener if the
  Keychain item is absent.
- `protonmcp http token rotate` — replace the 32 bytes, print the
  new token once to stdout, drop in-memory sessions. The previous
  token fails on the next request. The value is not an argument
  (it would show up in `ps`).
- `protonmcp http token revoke` — delete the Keychain item and drop
  sessions. The listener, if still up, answers `401` to everyone.
- `protonmcp http token show` — print the current token once, and
  only after a Touch ID approval. This is so you can paste it into
  the bot's header settings. It does not approve a send.
- `protonmcp http status` — enabled or not, listen address, whether
  a token exists, session count. Never the token.

Paste the printed value into Grok Bot's remote MCP header as
`Authorization: Bearer <token>`. One token means every holder is the
same caller. Rotating or revoking cuts them all off together.
Separate tokens per bot are out of scope.

### How a remote call moves through the existing gates

Order is fixed. Auth finishes before any of the gates below.

1. **Identity.** The HTTP handler puts a `caller.Caller` on the
   context and the middleware uses it whenever it is present.
   Today `FromContext` is ignored when `PID == 0`, and the
   middleware then records the daemon's parent (launchd). That
   fallback must not apply to HTTP. `FromContext` returns
   `(Caller, bool)`. HTTP sets `Transport: "http"`, `PID: 0`,
   `UID` of the daemon user, and `Label` from `caller_label` (your
   string, trimmed, max 64 characters, no control characters;
   default `remote`). The socket accept loop sets
   `Transport: "unix"` and keeps the peer's PID, UID, and binary.
   `initialize`'s client name is stored as `claimed_client` for the
   audit log and is never used to authorize.
2. **Lock.** The existing `resolveLock` path runs. A locked daemon
   raises the unlock Touch ID prompt on the Mac. One unlock prompt
   at a time, then a 60s cooldown if you do not approve, including
   if the client hangs up mid-prompt. `protonmcp unlock` still
   bypasses that cooldown. The remote caller cannot clear the lock
   itself.
3. **Idle.** A tool call that gets past the lock check bumps the
   existing idle tracker. Failed auth and a refused locked call do
   not. Screen lock and sleep still lock the daemon even if a bot
   is polling. An active bot resets the idle timer the same way
   Claude does.
4. **Audit begin, policy, rate limit, recipient allowlist,
   approval, handler, audit complete.** Unchanged order inside
   `Middleware.runTool`. Policy is the merged `default.yaml` plus
   your `policy.yaml`. A tool with no entry still fails closed.
5. **Approval dialog.** The Swift helper already appends
   `Requested by: <caller>`. `Caller.String()` for HTTP returns
   `http:<label>`, so the alert says who asked. Send-family tools
   still show every recipient, with counts, and still refuse an
   address or subject the dialog cannot show faithfully. `ttl: 0`
   tools, including every send, re-prompt every time.
6. **Cache key.** `approval.cacheKey` today is
   `sha256(tool || pid || args)`. Include transport and label. A
   cached `mail_move` approval from Claude must not satisfy the
   same call from HTTP, or the reverse. The cache is in memory
   only, so old entries simply miss after the upgrade and the user
   is prompted again.

There is no request field, header, or tool argument that sets
`approval_source`, seeds the cache, or skips the broker. If the
broker is missing, a `prompt` tool is denied, as it is today.

### Rate limits

Per-tool `rate_limit` in policy stays the mailbox cap. The bucket
key is currently `tool + "|" + pid`, so a new PID gets a fresh
budget and HTTP (PID 0) would double the cap next to Claude. Change
the key to the tool name only. Two local clients then share the
limit you configured. That is a tightening. Old per-PID rows in
`rate_limit_state` are left behind and no longer consulted.

On top of that, the HTTP listener has its own brakes. They do not
raise any policy cap:

- Authenticated requests: `max_requests_per_minute`, default 60,
  hard ceiling 600. Excess is HTTP `429`. Covers reads, which have
  no policy cap today.
- Failed auth: 10 per minute, then `429`. A scanner must not be
  able to hold a Touch ID dialog open.
- At most 2 authenticated HTTP requests in flight.
- At most one approval helper process at a time, for socket and
  HTTP together. A second prompted call returns a tool error
  immediately (`an approval prompt is already waiting on this Mac`)
  and does not queue. This matches the unlock gate: a remote caller
  must not stack dialogs.

### Rotate and revoke

| What you want | What you run | What happens |
|---|---|---|
| Cut off the network but keep the token | `protonmcp http disable`, and turn the tunnel off | Listener closes. Local socket still works. The public name stops answering once the tunnel is off. |
| Invalidate the secret, listener may stay up | `protonmcp http token revoke` | Keychain item deleted. Further HTTP requests are `401`. Sessions dropped. |
| Replace a token you pasted into a bot | `protonmcp http token rotate` | New 32 bytes, old value dead on the next request, new value printed once. Update the bot's header. |
| Pause without deleting | `protonmcp http disable` | Nothing is listening. `http enable` needs the token to still be there. |

Revoke is the application kill switch. Tunnel off is the network
kill switch. Use both if a token may have leaked. Logout does not
do either.

### Locked, declined, or timed out

The approval helper's own deadline stays 30 seconds
(`approval.Broker.helperTimeout`). The HTTP request context is 45
seconds, so the helper deadline fires first and the handler can
still record the outcome.

| Situation | What the Mac does | What the bot gets | Mail |
|---|---|---|---|
| Daemon locked, you approve the unlock prompt | Session comes back, then a write still shows its own approval | The call continues | A send has not happened yet |
| Daemon locked, you decline, dismiss, or 30s passes | Stays locked. 60s cooldown. WARN log, no audit row (same as today) | The existing locked error, `daemon is locked (<reason>) and the unlock prompt was not approved: ...` | Unchanged |
| Daemon locked, cooldown still running | No new prompt | The cooldown sentence, including the `protonmcp unlock` hint | Unchanged |
| Write prompt, you decline or 30s passes | Helper exits. Timeout is `ErrUserCanceled`, same as a dismiss | Tool error `user canceled <tool>` | Not sent, not filed, not deleted |
| Client disconnects during a prompt | Helper is killed. Unlock cooldown starts if this was the unlock prompt | Connection drops | Not sent |
| Screen re-locks during the prompt | `resolveLock` sees the new lock | `daemon re-locked (<reason>) before the call could run; retry` | Not sent |
| Prompt tool while another prompt is up | Second helper is not started | Tool error that a prompt is already waiting | Not sent |

A timeout or a cancel is audit `outcome=denied` when the call had
already entered `runTool` (the write prompt). A lock refusal that
returns before `audit.Begin` stays a WARN line only, which is the
current rule in `docs/configuration.md`. Neither path runs the tool
handler.

## 3. Tunnel

The daemon does not open a public port. You point a tunnel at
`127.0.0.1:4765` and add that tunnel's hostname to `allowed_hosts`.
Do not point the tunnel at the Unix socket, and do not use a tunnel
mode that serves files from disk.

- **Tailscale Funnel (recommended).** Public HTTPS name, no inbound
  port on the Mac, TLS ends in `tailscaled` on the Mac so Tailscale's
  relays cannot read the mail or the token; requires an open-source
  Mac build (the App Store app cannot funnel); the name is still on
  the internet, so the token is what keeps strangers out.
- **Cloudflare Tunnel.** Also outbound-only and not Google, but
  Cloudflare terminates TLS and can read the token and the mail.
- **ngrok.** The vendor terminates TLS and can read the traffic,
  and you take on another account and another long-running binary.
- **WireGuard or SSH to a VPS you run, with TLS ended on the Mac.**
  The VPS sees ciphertext only and there is no Google, but you now
  patch and watch a second computer, which is a larger attack
  surface than Funnel.
- **Tailscale Serve (tailnet only).** Stays off the public
  internet, but Grok Bot's servers are not on your tailnet and
  nothing can be installed there, so it cannot reach the bot.
- **Public relays such as localhost.run or bore.** Shared servers
  and thin authentication, and the relay can often see or tamper
  with the stream.
- **A Google front end (Cloud Run, Identity-Aware Proxy, and
  similar).** Ruled out.

Use Tailscale Funnel. It adds no second machine, it does not hand
plaintext to the relay, and it is not Google. `tailscaled` on the
Mac does see plaintext, because it terminates TLS before proxying to
localhost; that process is inside the trust boundary
`docs/security.md` already accepts for code running on your Mac.
Check Certificate Transparency if you want to confirm Tailscale is
not issuing a certificate that would let the relay terminate TLS.

Funnel's public ports are 443, 8443, and 10000. Point one of them at
`http://127.0.0.1:4765`. Turn Funnel off when you are not using the
bot. The Mac being asleep or offline stops the tunnel; the daemon
also locks on sleep.

## 4. Threat model delta

Compared with `docs/security.md` as it stands. That document is
still the description of what the shipped daemon does. This section
is what the network door adds. Issue 4 below copies the lasting
parts into `docs/security.md` when the code exists.

### Unchanged

- Proton login, the session item, and the mirror key stay as they
  are. This plan does not touch SRP, 2FA, or `go-proton-api`.
- Writes stay default-deny plus a Touch ID prompt that shows the
  literal recipients. Sends stay `ttl: 0`.
- Screen lock, sleep, and idle lock still drop the in-memory
  session. A screen unlock still does not unlock the daemon.
- The sealed `store.db` still does nothing for someone holding the
  Keychain, and nothing for a process running as you. It also does
  not cover tool results after they leave the daemon.
- A person at an unlocked logged-in Mac, and a Proton-side
  compromise, stay out of scope.
- The Unix socket's peer checks stay. They simply do not apply to
  the new listener.

### New

1. **A bearer holder can read the mailbox without Touch ID.** Reads
   are `allow` on purpose. Today that requires a same-UID process on
   the Mac. After this, it requires the token plus a path through
   the tunnel, while the Mac is awake and the daemon is unlocked.
   Grok Bot's servers see that mail text. That is the accepted
   trade-off. A leaked token is a remote read capability until you
   revoke it. Mitigations: 256-bit token, Keychain only, off by
   default, two kill switches, constant-time compare, no token in
   the query string or logs, HTTP rate limit on reads. None of
   those stop a patient holder of a live token. Revoke does.
2. **The Keychain ACL limit gets a new consequence.**
   `docs/security.md` already says a process running as you can read
   Keychain items without a fresh Touch ID. That now includes
   `http-bearer`. Local malware could copy it and use it from
   outside the house. The seal on `store.db` does not stop that.
   Mitigation is the same platform limit plus revoke, not a new
   Keychain entitlement (the restricted-entitlement wall in that
   doc still applies).
3. **Peer credentials no longer name the HTTP caller.** Without the
   identity change in section 2, HTTP calls would be audited as
   launchd. Mitigation: explicit `transport` and `caller_label`,
   and a claimed client name that is recorded and not trusted.
4. **Approval and rate-limit state could leak across callers.** A
   PID-0 cache key would let HTTP reuse a local cached approval
   inside the TTL window (`mail_move`, `mail_label`, `mail_trash`,
   `mail_draft_delete`, `mail_download_attachment` are 5 minutes).
   A per-PID rate bucket would give HTTP its own copy of a cap you
   thought was global. Mitigations: cache key includes transport
   and label; rate buckets are per tool.
5. **Prompt fatigue from the network.** A token holder, or a
   hostile message steering the bot, can ask for unlock and send
   dialogs while you are not in the Claude window. The sensor still
   cannot be satisfied in software. Mitigations: the existing one
   unlock prompt and 60s cooldown; one approval dialog at a time;
   auth failure limit so strangers without the token cannot raise
   dialogs; the dialog says `Requested by: http:<label>`.
6. **The public name is guessable enough to be scanned.** Funnel
   publishes DNS. Unauthenticated requests get an empty `401` and
   hit the failure limit. The hostname is not the secret.
7. **A tunnel that terminates TLS in the wrong place reads
   everything.** Cloudflare Tunnel and ngrok can see the token and
   the mail. That is why section 3 rejects them. A mis-set Funnel
   mode that served disk instead of the one port would publish
   files; the setup note says to proxy only `127.0.0.1:4765`.
8. **DNS rebinding and a browser hitting loopback.** A public site
   can try to call `127.0.0.1:4765` from your browser. Mitigations:
   bind loopback only, reject a present Origin that you did not
   list, require an allowed Host, send no CORS headers, require the
   bearer. The token must not live in a browser.
9. **DoS against the daemon.** A flood on the public name can burn
   CPU or hold connections. Auth runs first. Body cap, concurrency
   cap, and the auth-failure limit bound it. The Unix socket keeps
   working if you disable HTTP. Funnel also has its own bandwidth
   cap.
10. **Idle lock vs a polling bot.** Successful tool calls bump
    activity, so a bot that keeps reading holds the idle timer off.
    Screen lock and sleep still lock. Set `idle_lock_minutes` if you
    want a backstop, knowing an active bot resets it.

`docs/security.md` should gain, when this ships: the HTTP listener
under Defended (loopback, bearer, no policy bypass), the read-via-token
risk and the tunnel-termination risk under accepted risks, and a
line that the mirror seal does not cover bot-visible mail text.

## 5. Test plan

No real mailbox, no Proton account, no call to Proton, and no token
committed to the tree. Use a temp directory, the in-memory
`mcp.Server` with a dummy tool (the middleware tests already do
this), a fake approval helper that exits 0, 1, or sleeps, and a
Keychain fake on the non-macOS path (the same split as
`storekey_other.go`). `httptest` binds loopback; also call the
listen wrapper directly for the reject cases.

- **Default off.** No `http.yaml`, and `enabled: false`, both leave
  no TCP socket. The Unix socket path and mode are unchanged.
- **Bind.** `127.0.0.1` and `::1` succeed. `0.0.0.0`, a non-loopback
  IP, an empty host, and `localhost` as a name fail before listen.
  A connection whose `RemoteAddr` is not loopback is dropped. No
  other package calls `net.Listen("tcp")`.
- **Auth.** Missing header, wrong token, short token, and token in
  the query string are `401` with an empty body. The dummy tool is
  not called. Logs and audit contain no token bytes. Equal-length
  mismatches go through `ConstantTimeCompare` (assert the compare
  helper, not wall-clock timing).
- **Keychain lifetime.** Rotate replaces the bytes and the old
  value fails. Revoke deletes the item and the next request is
  `401`. `keystore.Delete` (logout) leaves `http-bearer` and
  `store-key` in place. `token show` is refused by a helper that
  exits 1 and prints nothing.
- **Protocol.** `initialize` returns `2025-06-18` and a session id.
  `tools/call` without the initialized notification is an error.
  GET and OPTIONS are `405` and set no CORS header. A bad
  `MCP-Protocol-Version` is `400`. Body over 8 MiB is `413`.
- **Host and Origin.** Unknown Host is `403`. A present unknown
  Origin is `403`. Missing Origin with a good token reaches the
  tool. `X-Forwarded-For` does not change identity.
- **Policy.** A `deny` tool does not call the helper. A `prompt`
  tool does. No header or argument flips the decision. A dummy
  send-shaped tool with `ttl: 0` calls the helper on every request.
- **Cache and rate.** An approval recorded for `transport=unix`
  does not hit for `transport=http` with the same tool, PID, and
  args. Two callers share one per-tool rate bucket; the second
  over-cap call is `denied` for both.
- **Lock and timeout.** Locked runtime: helper exit 1 returns the
  locked error and does not run the tool; no audit row. Helper
  that sleeps past 30s: tool error `user canceled`, audit
  `denied`, handler not called. A second prompted call while the
  first helper is in flight does not start another helper.
- **Idle.** A `401` does not move the activity timestamp. A
  successful dummy tool call does.
- **Audit.** The HTTP row has `transport=http`, the configured
  label, and the claimed client string. Args go through
  `redact.JSON`. A socket row still has `transport=unix` and the
  peer PID.
- **Dialog string.** The JSON handed to the fake helper contains
  `Requested by` input equal to `http:<label>`, not a client-supplied
  name.
- **Regression.** Existing middleware, approval, daemon socket, and
  policy tests pass. `go test ./...` is the bar. Do not point any
  test at Application Support or a live `store.db`.

## 6. Work breakdown

Do these in order. Each is one PR. Do not open the issues from this
file until you mean to build them. 1–3 leave the listener off, so
merging them does not expose a mailbox. Do not turn the tunnel on
until 4 has updated `docs/security.md`.

### 1. Record transport and caller, and stop cross-caller reuse

**Scope.** `caller.Caller` gains `Transport` and `Label`.
`FromContext` returns `(Caller, bool)`. The socket accept loop in
`cmd/protonmcpd/main.go` sets `Transport: "unix"`. Middleware treats
a present caller as authoritative even when PID is 0.
`approval.cacheKey` includes transport and label.
`(*caller.Caller).String()` returns `http:<label>` for HTTP so the
existing Touch ID helper text is honest. The rate-limit key becomes
the tool name only. A new goose migration adds `transport`,
`caller_label`, and `claimed_client` to `audit_log`; `Begin` /
`Complete` and the JSONL line write them. Unix rows leave
`claimed_client` empty.

Files: `internal/caller/`, `internal/mcp/middleware.go`,
`internal/mcp/rate_limit.go`, `internal/approval/cache.go`,
`internal/audit/`, `internal/store/migrations/`,
`cmd/protonmcpd/main.go`, and the tests next to those files.

**Acceptance.** A synthetic HTTP caller with PID 0 is audited as
`http` and the configured label, not as launchd. A unix-cached
approval is not a hit for HTTP. Two PIDs share one rate bucket.
Existing socket tests pass. No network listener in this PR.

### 2. Keychain token and the local CLI

**Scope.** New Keychain account `http-bearer` under
`zone.dort.protonmcp`, Darwin and non-Darwin files following
`internal/keystore/storekey_*.go`, held in `secret.Secret`.
Constant-time compare helper. CLI subcommands from section 2
(`enable`, `disable`, `status`, `token rotate`, `token revoke`,
`token show`). `http.yaml` read and written mode `0600`. Enable
refuses when the item is absent. `token show` goes through the
approval broker and prints nothing on decline. Rotate and revoke
do not take the secret on argv. Logout stays on
`keystore.Delete` and must not remove the new item.

Files: `internal/keystore/`, `cmd/protonmcp/main.go`, a new
`cmd/protonmcp/http.go`, tests.

**Acceptance.** The behaviors in the test-plan Keychain bullets,
including logout leaving the item in place. Status output has no
secret. Still no TCP listener.

### 3. Localhost Streamable HTTP on the daemon

**Scope.** Loopback listen wrapper and the `/mcp` handler from
section 2: auth, Host, Origin, body cap, session cap, protocol
header, `405` for GET and OPTIONS, no CORS. Wire a passing request
into `(*mcp.Server).dispatch` with the HTTP caller on the context,
so lock, policy, rate limit, approval, idle bump, and audit are the
existing code. On `initialize`, copy `clientInfo.name` onto the
session and pass it as `claimed_client` on later tool audits. Apply the HTTP request limit, the auth-failure
limit, the two-request cap, and the single global approval helper.
SIGHUP re-reads `http.yaml` and starts or stops the listener. Each
request loads the token from the Keychain. `protonmcp doctor`
gains a line for HTTP on/off and whether a token exists, never the
token. Update the `trustguard.go` comment. Add the new package to
`.github/CODEOWNERS` next to `internal/mcp/`.

Files: new `internal/httpmcp/` (listen wrapper, handler, limits),
`cmd/protonmcpd/main.go`, `internal/mcp/trustguard.go`,
`internal/approval/broker.go` only for the single-flight guard,
`cmd/protonmcp/doctor.go`, `.github/CODEOWNERS`, tests.

**Acceptance.** The transport, policy, lock, timeout, idle, audit,
and dialog bullets in section 5. Disabled config opens no port.
Wrong token does not run a tool and does not start the helper.
Unix socket tests still pass.

### 4. Document the door in the security model

**Scope.** Docs only, after 3. Update `docs/security.md` with the
delta in section 4. Update `docs/configuration.md`,
`docs/cli-reference.md`, and `docs/architecture.md` so they no
longer say the daemon never listens on a network port: it listens
on loopback only when this is enabled, and the socket is unchanged.
Adjust the README "never a network port" line the same way. Do not
weaken the write-approval or lock wording.

**Acceptance.** A reader of `docs/security.md` can see the new read
risk, the tunnel-termination risk, and the mitigations without
opening this plan. The commands in section 2 match the CLI
reference. No code change beyond comments that those docs require.
