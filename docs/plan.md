# Remote MCP for Grok Bot

Plan only. This file does not enable anything. The daemon stays a
local Unix-socket server until the later changes below are written
and you turn them on.

The approved goal (16 Nov 2026): Grok Bot, and your other bots, can
search, read, file, draft, and send Proton mail through proto-mcp on
your Mac. Grok Bot can only connect to a remote HTTPS MCP endpoint.
It cannot open the Unix socket, and nothing in this plan runs on
Grok Bot's computer. The remote door is narrower than that goal on
purpose: filing stays off it, and so do permanent delete and draft
delete, until you add them.

## 1. For the owner

Today the mail bridge only talks to programs on your Mac, through a
private socket. Grok Bot lives somewhere else, so it cannot use that
socket.

The change adds a second door on the same daemon. The door listens
only on the Mac itself. A private encrypted tunnel forwards one
public HTTPS address to that door. The door is locked with a long
random password (a bearer token) kept in the macOS Keychain. It is
off until you turn it on.

Through that door the bot can search, read, draft, download an
attachment, move mail to Trash, and ask to send. Trash here means
the recoverable Trash folder, not a permanent delete. It cannot
empty Trash, delete a draft, or permanently delete a message unless
you add that tool, and a permanent delete stays denied by policy
even then. Downloading, trashing, and sending still stop for the
same approval prompt on the Mac screen. A send prompt names the real
recipients. A remote caller cannot skip a prompt, pre-approve it, or
loosen the rules. Trashing a message that is already in Trash is
refused and does not touch Proton.

Reading does not ask for Touch ID on every call. A bot that keeps
polling would hold the idle timer open forever, so the remote door
also has a hard limit: 8 hours after the last Touch ID, the next
remote call asks again, even if the bot never went quiet. You are
leaving macOS screen lock off. That is an accepted risk. Walking
away does not lock the session by itself. The 8-hour clock and the
Tailscale admin console are the backstops. `protonmcp doctor` warns
when screen lock is off. It does not block.

The token you paste lives in Grok Bot's connector settings, so that
account is part of the trust boundary. Turn on a passkey or 2FA
there before you paste it. If you are away from the Mac, disable
Funnel or the Mac's node in the Tailscale admin console. That cuts
the network. Revoking the token still requires the Mac.

Two costs you already accepted: mail text a bot reads passes through
Grok Bot's servers, and this only works while the Mac is awake and
online. The tunnel we recommend does not let the tunnel company read
that mail.

## Owner decisions

Decided 16 Nov 2026. Implement these values.

- (a) Decided. macOS screen lock stays off. Accepted risk, not a precondition. The 8-hour HTTP unlock clock and the Tailscale off-site kill switch are the backstops. `protonmcp doctor` and turn-on warn when screen lock is off, and they do not block.
- (b) Decided. Tailscale Funnel stays always on. Accepted risk: a permanent public endpoint and scanner traffic. Token auth, the auth-failure limit, the per-minute and daily caps, and the audit log are the controls.
- (c) Decided. Default remote tools are search, read, draft, send, `mail_download_attachment`, and `mail_trash` (move to Trash, recoverable). Permanent delete, empty Trash, and `mail_draft_delete` stay excluded unless you add them. The remote path refuses `mail_trash` when the message is already in Trash.

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
  stay as they are. `remote_tools` does not apply to it.
- One shared tool pipeline. HTTP calls `(*mcp.Server).dispatch` and
  then the same middleware as a socket client (`internal/mcp/server.go`,
  `internal/mcp/middleware.go`). No second policy engine, no second
  approval path.
- Remote requests cannot change `decision`, `confirm`, `ttl`,
  `allowed_recipients`, or `rate_limit`. `policy.Engine.Decide`
  keeps ignoring caller identity for the decision. There is no tool
  that edits policy. `remote_tools` can only remove tools from the
  HTTP path. It cannot turn a `deny` into `allow` or `prompt`.
- The advertised MCP version stays the existing constant
  `ProtocolVersion` (`2025-06-18` in `internal/mcp/types.go`).
- No OAuth, no second token, no code on Grok Bot's computer, no
  Proton protocol changes. The tunnel is something you run; it is
  not a proto-mcp feature.
- Secrets never go in git, logs, audit rows, process arguments, or
  stdout.

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
max_remote_reads_per_day: 500 # HTTP read calls per local day; 0 means this default, never unlimited
max_unlock_hours: 8           # wall clock since last Touch ID, for HTTP only; 0 means this default
# remote_tools: omitted means the built-in default below, not every tool.
# Setting it replaces that default. It cannot widen policy.
# remote_tools:
#   - account_whoami
#   - mail_list
#   - mail_search
#   - mail_read
#   - mail_read_thread
#   - mail_list_attachments
#   - mail_sync
#   - labels_list
#   - folders_list
#   - calendar_list
#   - calendar_events
#   - calendar_read_event
#   - mail_draft_list
#   - mail_draft_create
#   - mail_draft_update
#   - mail_send
#   - mail_send_draft
#   - mail_reply
#   - mail_reply_all
#   - mail_forward
#   - mail_download_attachment
#   - mail_trash
```

You add the tunnel's public hostname to `allowed_hosts` when you
turn the tunnel on. A Host or Origin that is not on the list is
rejected (`403`) before any tool runs. A missing Origin is allowed,
because non-browser MCP clients do not send one. A present Origin
must match an entry you listed. The value `null` is rejected. The
default list has no Origins, so a browser is refused.

`protonmcp policy reload` (SIGHUP) re-reads `http.yaml` and opens
or closes the listener even when the policy file failed to reload.
The previous policy stays in that case. The token is not cached:
each request reads it from the Keychain, so revoke is immediate.
Omitted or `0` for `max_unlock_hours` and the two rate caps means
the default. There is no value that means "never expire" or "no
cap". A number below 0, `max_unlock_hours` above 24, a rate above
its hard ceiling, or a `remote_tools` entry of `*` makes the file
unusable. The daemon treats an unusable file as disabled and closes
a listener it already opened. It does not keep the last good config.
A first load does not enable the listener.

### Remote tool scope

`remote_tools` is an allowlist checked only when `Transport` is
`http`, after policy `Decide` and before the handler. It narrows.
It does not widen.

- Omitted or empty means the built-in default, not "every registered
  tool". Empty must not be implemented as allow-all.
- A name not on the effective list is `outcome=denied`, the handler
  does not run, and the approval helper does not start. The Unix
  socket never consults the list.
- A name on the list whose policy is `deny` stays denied. Listing
  `mail_delete_permanent` does nothing, because that entry is `deny`.
  Listing a `prompt` tool still prompts. The allowlist cannot set
  `decision`.
- A name that is not a registered tool is ignored at load and does
  not create a tool. `*` and `all` are rejected as a bad file.
- Setting `remote_tools` replaces the default. To add one excluded
  tool, list the default names plus that tool. Deleting a line
  narrows further.

Built-in default (search, read, draft, send, attachment download,
recoverable trash):

`account_whoami`, `mail_list`, `mail_search`, `mail_read`,
`mail_read_thread`, `mail_list_attachments`, `mail_sync`,
`labels_list`, `folders_list`, `calendar_list`, `calendar_events`,
`calendar_read_event`, `mail_draft_list`, `mail_draft_create`,
`mail_draft_update`, `mail_send`, `mail_send_draft`, `mail_reply`,
`mail_reply_all`, `mail_forward`, `mail_download_attachment`,
`mail_trash`.

Off the remote door unless you add them: `mail_save_attachment`,
`mail_draft_delete`, `labels_delete`, `folders_delete`, `mail_move`,
`mail_label`, `mail_mark_read`, `mail_mark_unread`, and the label
and folder create/update tools. There is no empty-Trash tool. If
one is added later, it stays off this list and `deny` in policy.
`mail_delete_permanent` stays denied by policy even if listed.
`mail_draft_delete` stays off even though today's handler only
applies the Trash label.

`mail_trash` on the remote path is move-to-Trash only. Today's
handler calls `LabelMessages` with the Trash label and does not call
`DeleteMessage`. The HTTP path still refuses, before the approval
cache and before the handler, when the mirror shows the message is
already in Trash, or when the mirror has no row to decide. That
refusal makes no Proton call. A later change that permanently
deleted on a second trash cannot be reached over HTTP. The Unix
socket does not gain this extra refusal.

The reason the destructive tools stay off is prompt injection. Mail
the bot reads is untrusted, and a hostile message can tell the bot
to delete a draft or destroy a message. Those tools are not on the
remote list. Download and recoverable trash are on the list and
still require Touch ID (`ttl` 5 minutes, cache key includes
transport). Sends stay on the list and still require Touch ID with
the real recipients, `ttl` 0. Draft create and update have no
external effect.

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
  Keychain item is absent. It does not refuse when screen lock is
  off. A best-effort read of `com.apple.screensaver`
  `askForPassword` that is not `1` prints a warning and still
  enables. `protonmcp doctor` prints the same warning. Neither
  blocks. Screen lock off is the accepted risk in decision (a).
- `protonmcp http token rotate` — replace the 32 bytes, copy the new
  token to the clipboard, and keep the process alive for about 60
  seconds with a countdown. Ctrl-C clears early. Clear only if the
  clipboard still holds that token. Do not write it to stdout,
  stderr, or a log. Drop in-memory sessions. The previous token fails
  on the next request. The value is not an argument (it would show
  up in `ps`). Universal Clipboard can copy the token to the owner's
  other Apple devices while it sits on the clipboard.
- `protonmcp http token revoke` — delete the Keychain item and drop
  sessions. The listener, if still up, answers `401` to everyone.
- `protonmcp http token show` — same clipboard copy and 60-second
  clear, and only after a Touch ID approval. Decline copies nothing.
  This does not approve a send.
- `protonmcp http status` — enabled or not, listen address, whether
  a token exists, session count, age of the HTTP unlock clock, and
  whether the daemon is actually listening. The live numbers come
  from the daemon's status file and are shown only while that
  process is still running. Never the token. `doctor` says the door
  is listening whenever that process still has the listener open.
- `protonmcp http activity` — counts of remote tool calls from the
  audit log. See below.

The clipboard helper compares before clearing, so a value you copied
afterward is left alone. Tests use a fake pasteboard. A non-macOS
build returns an error and does not print the secret.

Where you paste it: Grok Bot's remote MCP connector header,
`Authorization: Bearer <token>`. That copy lives in Grok Bot's
settings, on Grok Bot's servers. The Grok Bot account is inside the
trust boundary. Require a passkey or 2FA on it before pasting.
Someone who can open the account can use the token until you revoke
it or take the tunnel down. One token means every holder is the same
caller. Rotating or revoking cuts them all off together. Separate
tokens per bot are out of scope.

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
2. **Absolute HTTP unlock.** Separate from idle. Stamp a wall-clock
   time on every successful Touch ID that unlocks the session
   (startup, `protonmcp unlock`, or `resolveLock`). HTTP calls also
   stamp it when the absolute-lifetime prompt below succeeds.
   `max_unlock_hours` (default 8, allowed 1–24, no unlimited value)
   is measured from that stamp. When the age exceeds it, the next
   HTTP tool call raises Touch ID before the tool runs, even if the
   daemon is unlocked and the idle timer was just bumped. Approval
   resets the stamp and the call continues. Decline, dismiss, or the
   30s helper timeout leaves the stamp unchanged, does not run the
   tool, and uses the same cooldown as a refused unlock. Unix-socket
   calls do not read this clock and are not locked by it. A polling
   bot cannot extend the stamp.
3. **Lock.** The existing `resolveLock` path runs when the daemon is
   actually locked. A locked daemon raises the unlock Touch ID
   prompt on the Mac. One unlock prompt at a time, then a 60s
   cooldown if you do not approve, including if the client hangs up
   mid-prompt. `protonmcp unlock` still bypasses that cooldown. The
   remote caller cannot clear the lock itself. A successful unlock
   resets the HTTP stamp from step 2.
4. **Idle.** A tool call that gets past the lock check bumps the
   existing idle tracker. Failed auth, a refused locked call, and
   the absolute-lifetime check do not. Screen lock and sleep still
   lock the daemon even if a bot is polling. Idle is not the remote
   backstop. The 8-hour stamp is.
5. **Audit begin, policy, remote allowlist, rate limit, recipient
   allowlist, approval, handler, audit complete.** Policy is the
   merged `default.yaml` plus your `policy.yaml`. A tool with no
   entry still fails closed. The remote allowlist runs only for
   `transport=http`, after `Decide`, and cannot override it.
6. **Approval dialog.** The Swift helper already appends
   `Requested by: <caller>`. `Caller.String()` for HTTP returns
   `http:<label>`, so the alert says who asked. Send-family tools
   still show every recipient, with counts, and still refuse an
   address or subject the dialog cannot show faithfully. `ttl: 0`
   tools, including every send, re-prompt every time.
7. **Cache key.** `approval.cacheKey` today is
   `sha256(tool || pid || args)`. Include transport and label. A
   cached `mail_move` approval from Claude must not satisfy the
   same call from HTTP, or the reverse. The cache is in memory
   only, so old entries simply miss after the upgrade and the user
   is prompted again.

There is no request field, header, or tool argument that sets
`approval_source`, seeds the cache, or skips the broker. If the
broker is missing, a `prompt` tool is denied, as it is today.

Every HTTP `tools/call` that passes auth writes an audit row,
including reads and including a call the allowlist or the daily cap
denies. The row stores tool name, transport, caller label, claimed
client, outcome, and args after `redact.JSON`. That redactor already
keeps `message_id` (and the other opaque ids) literal and replaces
body fields with `{sha256, bytes}`. Do not add a path that stores
the body. Failed auth is still not a tool call: WARN only, no row,
no token bytes.

`protonmcp http activity` reads those rows for `transport=http` and
prints, for today and the previous 7 local days, the count by tool
and outcome. It prints message ids only when you pass a flag that
asks for them, and it never prints a body, subject, or recipient.
Once a local day, the daemon posts one macOS notification via
`osascript display notification` (no new entitlement) with that
day's remote call counts: total, reads, sends, denials. If the Mac
was asleep at midnight, it posts for the completed day the next
time the daemon is running, and it does not post twice for the same
day. The text is counts only. If that day's remote count is zero,
it posts nothing.
A fake notifier in tests records the text.

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
  hard ceiling 600. Excess is HTTP `429`.
- Remote reads: `max_remote_reads_per_day`, default 500, hard
  ceiling 5000, counted in the local timezone and stored in SQLite
  so a restart does not reset the day. A read call is one of
  `account_whoami`, `mail_list`, `mail_search`, `mail_read`,
  `mail_read_thread`, `mail_list_attachments`, `mail_draft_list`,
  `labels_list`, `folders_list`, `calendar_list`, `calendar_events`,
  `calendar_read_event`, `mail_download_attachment`. `mail_sync`,
  drafts, sends, and `mail_trash` do not consume it. Over the cap
  the call is `outcome=denied`, the handler does not run, and the
  Unix socket is unaffected. `0` in the file means the default, not
  unlimited.
- Failed auth: 10 per minute, then `429`, one bucket for the whole
  listener. A scanner must not be able to hold a Touch ID dialog
  open. The same bucket locks the real bot out for the rest of the
  window. That is accepted. Every connection arrives from loopback,
  so splitting the bucket by address would not separate the scanner
  from the bot. Do not split it.
- At most 2 authenticated HTTP requests in flight.
- At most one approval helper process at a time, for socket and
  HTTP together. A second prompted call returns a tool error
  immediately (`an approval prompt is already waiting on this Mac`)
  and does not queue. This matches the unlock gate: a remote caller
  must not stack dialogs.

### Rotate, revoke, and the off-site kill switch

| What you want | What you run | What happens |
|---|---|---|
| Cut the network while you are not at the Mac | Tailscale admin console: disable Funnel, or disable this node | The public name stops answering. The daemon may still be listening on loopback. The token is unchanged. |
| Cut off the network from the Mac but keep the token | `protonmcp http disable`, and turn Funnel off | Listener closes. Local socket still works. |
| Invalidate the secret, listener may stay up | `protonmcp http token revoke` | Keychain item deleted. Further HTTP requests are `401`. Sessions dropped. The copy in Grok Bot's connector dies with it. |
| Replace a token you pasted into a bot | `protonmcp http token rotate` | New 32 bytes on the clipboard for about 60 seconds, old value dead on the next request. Update the bot's header. |
| Pause without deleting | `protonmcp http disable` | Nothing is listening. `http enable` needs the token to still be there. Screen lock off does not block it. |

Use the Tailscale admin console when you cannot reach the Mac. That
is the off-site kill switch for the recommended tunnel. Disabling
the node is the stronger of the two; disabling Funnel leaves the
tailnet up and removes the public name. Revoke still needs the Mac,
or a later visit, because the Keychain item is local. Logout does
not revoke and does not disable Funnel.

The token in Grok Bot's connector is a second copy. Treat a
compromise of that account like a leaked token: disable Funnel from
the admin console, then revoke when you are back at the Mac.

### Locked, declined, or timed out

The approval helper's own deadline stays 30 seconds
(`approval.Broker.helperTimeout`). The HTTP request context is 45
seconds, so the helper deadline fires first and the handler can
still record the outcome.

| Situation | What the Mac does | What the bot gets | Mail |
|---|---|---|---|
| Daemon locked, you approve the unlock prompt | Session comes back, HTTP stamp resets, then a write still shows its own approval | The call continues | A send has not happened yet |
| HTTP unlock older than `max_unlock_hours`, daemon otherwise unlocked | Touch ID prompt. Approval resets the stamp. Decline leaves the local session up | On decline, the call stops | Not read and not sent by this call |
| Daemon locked, you decline, dismiss, or 30s passes | Stays locked. 60s cooldown. WARN log, no audit row (same as today) | The existing locked error, `daemon is locked (<reason>) and the unlock prompt was not approved: ...` | Unchanged |
| Daemon locked, cooldown still running | No new prompt | The cooldown sentence, including the `protonmcp unlock` hint | Unchanged |
| Write prompt, you decline or 30s passes | Helper exits. Timeout is `ErrUserCanceled`, same as a dismiss | Tool error `user canceled <tool>` | Not sent, not filed, not deleted |
| Client disconnects during a prompt | Helper is killed. Unlock cooldown starts if this was the unlock prompt | Connection drops | Not sent |
| Screen re-locks during the prompt | `resolveLock` sees the new lock | `daemon re-locked (<reason>) before the call could run; retry` | Not sent |
| Prompt tool while another prompt is up | Second helper is not started | Tool error that a prompt is already waiting | Not sent |
| Tool not on `remote_tools` | No prompt | Tool error, audit `denied` | Unchanged |
| `mail_trash` and the message is already in Trash, or the mirror cannot say | No prompt, no Proton call | Tool error, audit `denied` | Unchanged |
| Daily read cap exceeded | No prompt | Tool error, audit `denied` | Not read by this call |

A timeout or a cancel is audit `outcome=denied` when the call had
already entered `runTool` (the write prompt). A lock refusal that
returns before `audit.Begin` stays a WARN line only, which is the
current rule in `docs/configuration.md`. An HTTP `tools/call` that
is denied by the allowlist or the daily cap has already entered
`runTool`, so it gets a row. None of these paths run the tool
handler.

### Turn-on steps

1. Leave macOS screen lock off. That is decision (a). `protonmcp
   doctor` and `http enable` warn. They do not block. The backstops
   are the 8-hour HTTP unlock clock and the Tailscale admin console.
2. On the Grok Bot account, turn on a passkey or 2FA. The token will
   live in that account's connector settings.
3. `protonmcp http token rotate`. The token is on the clipboard for
   about 60 seconds. Paste it into the connector header
   `Authorization: Bearer <token>`.
4. `protonmcp http enable`. Refuses without a token. Warns if screen
   lock is off, and still enables.
5. Start Tailscale Funnel to `http://127.0.0.1:4765` and leave it on.
   That is decision (b). Add the hostname to `allowed_hosts`. The
   public name stays up, so scanner traffic is expected. The kill
   switch, when you need it, is the Tailscale admin console: disable
   Funnel, or disable the node.
6. Leave `remote_tools` unset. The default includes
   `mail_download_attachment` and `mail_trash`. Adding
   `mail_draft_delete` means listing the default names plus that
   tool. Listing `mail_delete_permanent` does not enable it.

## 3. Tunnel

The daemon does not open a public port. You point a tunnel at
`127.0.0.1:4765` and add that tunnel's hostname to `allowed_hosts`.
Do not point the tunnel at the Unix socket, and do not use a tunnel
mode that serves files from disk.

- **Tailscale Funnel (recommended).** Public HTTPS name, no inbound
  port on the Mac, TLS ends in `tailscaled` on the Mac so Tailscale's
  relays cannot read the mail or the token; requires an open-source
  Mac build (the App Store app cannot funnel); the name is still on
  the internet, so the token is what keeps strangers out. The admin
  console can disable Funnel or the node when you are not at the Mac.
- **Cloudflare Tunnel.** Also outbound-only and not Google, but
  Cloudflare terminates TLS and can read the token and the mail.
- **ngrok.** The vendor terminates TLS and can read the traffic,
  and you take on another account and another long-running binary.
- **WireGuard or SSH to a VPS you run, with TLS ended on the Mac.**
  The VPS sees ciphertext only and there is no Google, but you now
  patch and watch a second computer, which is a larger attack
  surface than Funnel. The off-site kill switch would be that VPS's
  firewall, which is another host to reach.
- **Tailscale Serve (tailnet only).** Stays off the public
  internet, but Grok Bot's servers are not on your tailnet and
  nothing can be installed there, so it cannot reach the bot.
- **Public relays such as localhost.run or bore.** Shared servers
  and thin authentication, and the relay can often see or tamper
  with the stream.
- **A Google front end (Cloud Run, Identity-Aware Proxy, and
  similar).** Ruled out.

Use Tailscale Funnel, and leave it on (decision (b)). That is a
permanent public endpoint. Scanners will hit it. The controls are
the bearer token, the auth-failure limit, the per-minute and daily
caps, and the audit log. Funnel adds no second machine, it does not
hand plaintext to the relay, and it is not Google. `tailscaled` on the Mac does see plaintext, because it
terminates TLS before proxying to localhost; that process is inside
the trust boundary `docs/security.md` already accepts for code
running on your Mac. Check Certificate Transparency if you want to
confirm Tailscale is not issuing a certificate that would let the
relay terminate TLS.

Funnel's public ports are 443, 8443, and 10000. Point one of them at
`http://127.0.0.1:4765`. The Mac being asleep or offline stops the
tunnel; the daemon also locks on sleep. From another device, the
Tailscale admin console is the kill switch: disable Funnel, or
disable the node.

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
- Sleep and idle lock still drop the in-memory session when they
  fire. A screen unlock still does not unlock the daemon. Screen
  lock itself is off by owner decision, so it will not be the thing
  that fires.
- The sealed `store.db` still does nothing for someone holding the
  Keychain, and nothing for a process running as you. It also does
  not cover tool results after they leave the daemon.
- A person at an unlocked logged-in Mac, and a Proton-side
  compromise, stay out of scope.
- The Unix socket's peer checks stay. They simply do not apply to
  the new listener.

### New

1. **A bearer holder can read the mailbox without Touch ID, until
   the unlock clock runs out.** Reads on the allowlist are `allow`
   on purpose. Today that requires a same-UID process on the Mac.
   After this, it requires the token plus a path through the tunnel,
   while the Mac is awake, the daemon is unlocked, and the HTTP
   stamp is younger than `max_unlock_hours`. Grok Bot's servers see
   that mail text. That is the accepted trade-off. A leaked token is
   a remote read capability until the stamp expires, you revoke, or
   you take the tunnel down. Mitigations: 256-bit token, Keychain
   only, off by default, clipboard clear, the 8-hour stamp, the
   daily read cap, the remote allowlist, constant-time compare, no
   token in the query string or logs. None of those stop a patient
   holder of a live token inside the 8-hour window. Revoke, or
   disabling Funnel, does.
2. **The Grok Bot account holds a copy of the token.** Connector
   settings are on Grok Bot's servers. That account is inside the
   trust boundary. Mitigation: passkey or 2FA required before you
   paste, and the Tailscale admin console as the kill switch that
   does not need the Mac. Revoke when you are home.
3. **The Keychain ACL limit gets a new consequence.**
   `docs/security.md` already says a process running as you can read
   Keychain items without a fresh Touch ID. That now includes
   `http-bearer`. Local malware could copy it and use it from
   outside the house. The seal on `store.db` does not stop that.
   Mitigation is the same platform limit plus revoke and Funnel off,
   not a new Keychain entitlement (the restricted-entitlement wall
   in that doc still applies).
4. **Peer credentials no longer name the HTTP caller.** Without the
   identity change in section 2, HTTP calls would be audited as
   launchd. Mitigation: explicit `transport` and `caller_label`,
   and a claimed client name that is recorded and not trusted.
   Every HTTP tool call, reads included, writes a redacted row.
5. **Approval and rate-limit state could leak across callers.** A
   PID-0 cache key would let HTTP reuse a local cached approval
   inside the TTL window (`mail_move`, `mail_label`, `mail_trash`,
   `mail_draft_delete`, `mail_download_attachment` are 5 minutes).
   A per-PID rate bucket would give HTTP its own copy of a cap you
   thought was global. Mitigations: cache key includes transport
   and label; rate buckets are per tool. `mail_move`,
   `mail_label`, and `mail_draft_delete` stay off the default
   remote list. `mail_trash` and `mail_download_attachment` are on
   it, so the cache key is what stops a local approval covering
   them. The list is not a substitute for the cache key.
6. **Prompt injection from mail the bot reads.** A hostile message
   can instruct the bot to trash, delete, download an attachment,
   or send. Download and recoverable trash are on the default list
   and still require Touch ID. A second trash, of a message already
   in Trash, is refused before any Proton call. Permanent delete,
   empty Trash, and `mail_draft_delete` are not on the list, and
   adding a name cannot beat a policy `deny`. Sends require Touch
   ID showing the real recipients, `ttl` 0. Filing stays off the
   default list.
7. **Prompt fatigue from the network.** A token holder, or a
   hostile message steering the bot, can ask for unlock and send
   dialogs while you are not in the Claude window. The sensor still
   cannot be satisfied in software. Mitigations: the existing one
   unlock prompt and 60s cooldown; the 8-hour re-prompt; one
   approval dialog at a time; auth failure limit so strangers
   without the token cannot raise dialogs; the dialog says
   `Requested by: http:<label>`.
8. **The public name stays up.** Decision (b) leaves Funnel always
   on, so the endpoint is permanent and scanners will hit it. That
   is accepted. Unauthenticated requests get an empty `401` and hit
   the failure limit. The hostname is not the secret. A live token
   still has to pass the per-minute cap, the daily read cap, the
   allowlist, and the audit log. The shared failure bucket will
   also `429` the real bot for the rest of that minute. Accepted.
9. **A tunnel that terminates TLS in the wrong place reads
   everything.** Cloudflare Tunnel and ngrok can see the token and
   the mail. That is why section 3 rejects them. A mis-set Funnel
   mode that served disk instead of the one port would publish
   files; the setup note says to proxy only `127.0.0.1:4765`.
10. **DNS rebinding and a browser hitting loopback.** A public site
    can try to call `127.0.0.1:4765` from your browser. Mitigations:
    bind loopback only, reject a present Origin that you did not
    list, require an allowed Host, send no CORS headers, require the
    bearer. The token must not live in a browser. The clipboard
    clear is so a local paste does not sit there.
11. **DoS against the daemon.** A flood on the public name can burn
    CPU or hold connections. Auth runs first. Body cap, concurrency
    cap, and the auth-failure limit bound it. The Unix socket keeps
    working if you disable HTTP. Funnel also has its own bandwidth
    cap. Disabling Funnel from the admin console stops the flood
    without touching the daemon.
12. **Screen lock is off, and a polling bot holds idle open.**
    Successful tool calls bump activity, so a bot that keeps reading
    holds the idle timer off. Screen lock will not fire, because
    decision (a) leaves it off. That is an accepted risk. Sleep
    still locks the daemon. The stated backstops are the HTTP
    wall-clock stamp, which idle cannot move, and the Tailscale
    admin console. `protonmcp doctor` warns. It does not block.

`docs/security.md` should gain, when this ships: the HTTP listener
under Defended (loopback, bearer, allowlist that only narrows,
absolute unlock lifetime, remote trash that refuses a message
already in Trash), the read-via-token risk, the Grok account as a
trust boundary, the Tailscale admin-console kill switch, the
accepted risks of screen lock off and an always-on Funnel, the
accepted auth-failure lockout, and a line that the mirror seal does
not cover bot-visible mail text.

## 5. Test plan

No real mailbox, no Proton account, no call to Proton, and no token
committed to the tree. Use a temp directory, the in-memory
`mcp.Server` with a dummy tool (the middleware tests already do
this), a fake approval helper that exits 0, 1, or sleeps, and a
Keychain fake on the non-macOS path (the same split as
`storekey_other.go`). `httptest` binds loopback; also call the
listen wrapper directly for the reject cases. Clipboard and
notification tests use fakes, not the real pasteboard.

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
  `store-key` in place. `token show` and `token rotate` copy to the
  fake pasteboard and do not write stdout. A helper that exits 1
  leaves the pasteboard untouched. The clear runs only when the
  pasteboard still holds the token after about 60 seconds.
- **Screen lock warning.** With the screensaver check faked off
  and a token present, `http enable` still writes `enabled: true`
  and the output warns. `doctor` warns. Neither refuses. With the
  check faked on, there is no screen-lock warning.
- **Protocol.** `initialize` returns `2025-06-18` and a session id.
  `tools/call` without the initialized notification is an error.
  GET and OPTIONS are `405` and set no CORS header. A bad
  `MCP-Protocol-Version` is `400`. Body over 8 MiB is `413`.
- **Host and Origin.** Unknown Host is `403`. A present unknown
  Origin is `403`. The Origin value `null` is `403`. Missing Origin
  with a good token reaches the tool. `X-Forwarded-For` does not
  change identity.
- **Policy and remote scope.** A `deny` tool does not call the
  helper, even if listed in `remote_tools`. A listed `prompt` tool
  does. No header or argument flips the decision. A dummy
  send-shaped tool with `ttl: 0` calls the helper on every request.
  With the default list, HTTP `mail_download_attachment` and
  `mail_trash` of a message the mirror says is not in Trash reach
  the prompt. HTTP `mail_draft_delete` and `mail_delete_permanent`
  are denied and do not start the helper. The same calls on the
  Unix socket still follow policy. `mail_trash` over HTTP, when the
  mirror says the message is already in Trash or has no row, is
  denied before the approval cache and before the handler: no
  helper, no `LabelMessages`, no `DeleteMessage`. A Unix
  `mail_trash` of that same message still follows today's handler.
  `*` is a bad file and does not enable the listener.
- **Cache and rate.** An approval recorded for `transport=unix`
  does not hit for `transport=http` with the same tool, PID, and
  args. Two callers share one per-tool rate bucket; the second
  over-cap call is `denied` for both. The 501st HTTP read call in a
  local day is denied, a restart does not zero the counter, and a
  Unix read of the same tool still runs.
- **Absolute unlock.** A fake clock 8 hours and 1 minute past the
  last Touch ID makes the next HTTP call raise the helper even
  though the daemon is unlocked and a tool call just bumped idle.
  Helper exit 0 resets the stamp and runs the tool. Helper exit 1
  does not run the tool and does not lock the local session. A
  Unix call at the same moment does not raise that prompt. A stream
  of successful HTTP reads does not move the stamp.
- **Lock and timeout.** Locked runtime: helper exit 1 returns the
  locked error and does not run the tool; no audit row. Helper
  that sleeps past 30s: tool error `user canceled`, audit
  `denied`, handler not called. A second prompted call while the
  first helper is in flight does not start another helper.
- **Idle.** A `401` does not move the activity timestamp. A
  successful dummy tool call does. That bump does not extend the
  HTTP unlock stamp.
- **Auth-failure lockout.** Eleven failed auths in a minute produce
  `429` for a later request that has the right token. This is the
  accepted shared bucket, covered by a comment on the test.
- **Audit.** Every HTTP `tools/call` that passes auth, including a
  read and including an allowlist denial, has a row with
  `transport=http`, the configured label, and the claimed client
  string. Args go through `redact.JSON`: a `message_id` is still
  literal, a body field is `{sha256, bytes}` only. A socket row
  still has `transport=unix` and the peer PID. `http activity`
  prints counts and does not contain a body fixture planted in the
  row. The fake daily notification receives counts and no body, and
  it is not called when the day's remote count is zero.
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
until 4 has updated `docs/security.md`. Implement the decided
values in the Owner decisions section.

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
`claimed_client` empty. No tool-call path skips the audit row for a
read.

Files: `internal/caller/`, `internal/mcp/middleware.go`,
`internal/mcp/rate_limit.go`, `internal/approval/cache.go`,
`internal/audit/`, `internal/store/migrations/`,
`cmd/protonmcpd/main.go`, and the tests next to those files.

**Acceptance.** A synthetic HTTP caller with PID 0 is audited as
`http` and the configured label, not as launchd, for both an allow
(read) tool and a denied tool. The row's args keep `message_id`
literal and store a body only as `{sha256, bytes}`. A unix-cached
approval is not a hit for HTTP. Two PIDs share one rate bucket.
Existing socket tests pass. No network listener in this PR.

### 2. Keychain token and the local CLI

**Scope.** New Keychain account `http-bearer` under
`zone.dort.protonmcp`, Darwin and non-Darwin files following
`internal/keystore/storekey_*.go`, held in `secret.Secret`.
Constant-time compare helper. CLI subcommands from section 2
(`enable`, `disable`, `status`, `token rotate`, `token revoke`,
`token show`). `http.yaml` read and written mode `0600`, including
`max_unlock_hours`, `max_remote_reads_per_day`, and omitted
`remote_tools` meaning the default list, which includes
`mail_download_attachment` and `mail_trash` and excludes
`mail_draft_delete` and `mail_delete_permanent`. Enable refuses
when the item is absent. When the screensaver check is off it
warns and still writes `enabled: true` (decision (a)). `token show`
and `token rotate` copy to a pasteboard interface and schedule a
compare-and-clear at about 60 seconds.
They do not write the secret to stdout. Decline copies nothing.
Rotate and revoke do not take the secret on argv. Logout stays on
`keystore.Delete` and must not remove the new item.

Files: `internal/keystore/`, `cmd/protonmcp/main.go`, a new
`cmd/protonmcp/http.go`, tests with a fake pasteboard.

**Acceptance.** The Keychain and screen-lock bullets in section 5.
Enable with screen lock faked off still enables, and the warning
is present. Status output has no secret. The fake pasteboard
receives the token and is cleared only while it still holds it. A
non-macOS run of
show/rotate returns an error and prints nothing. Still no TCP
listener.

### 3. Localhost Streamable HTTP on the daemon

**Scope.** Loopback listen wrapper and the `/mcp` handler from
section 2: auth, Host, Origin, body cap, session cap, protocol
header, `405` for GET and OPTIONS, no CORS. Wire a passing request
into `(*mcp.Server).dispatch` with the HTTP caller on the context,
so lock, policy, rate limit, approval, idle bump, and audit are the
existing code. On `initialize`, copy `clientInfo.name` onto the
session and pass it as `claimed_client` on later tool audits. Apply
the HTTP request limit, the shared auth-failure limit, the daily
remote read cap, the two-request cap, and the single global approval
helper. Enforce `remote_tools` inside the middleware after `Decide`:
default list as in section 2, including `mail_download_attachment`
and `mail_trash`, Unix path ignores it, a listed `deny` stays
denied. On HTTP, `mail_trash` refuses before the approval cache
when the message is already in Trash or the mirror cannot say, and
that path calls neither `LabelMessages` nor `DeleteMessage`.
`mail_draft_delete` and any permanent-delete or empty-Trash tool
stay off the default list. Enforce `max_unlock_hours` as a
wall-clock stamp that idle bumps do not move, prompting Touch ID
for HTTP only. SIGHUP
re-reads `http.yaml` and starts or stops the listener. Each request
loads the token from the Keychain. `protonmcp doctor` gains a line
for HTTP on/off, whether a token exists, and a warning when screen
lock is off. Never the token. The warning does not fail the doctor
run. `protonmcp http activity` prints the counts from section 2.
A daily `osascript` notification posts counts only, and skips a day
with no remote calls. Update the `trustguard.go` comment. Add the
new package to `.github/CODEOWNERS` next to `internal/mcp/`.

Files: new `internal/httpmcp/` (listen wrapper, handler, limits,
unlock clock, allowlist), `cmd/protonmcpd/main.go`,
`internal/mcp/middleware.go` for the allowlist check,
`internal/mcp/trustguard.go`, `internal/approval/broker.go` only for
the single-flight guard, `cmd/protonmcp/doctor.go`,
`cmd/protonmcp/http.go` for `activity`, `.github/CODEOWNERS`, tests.

**Acceptance.** The transport, policy, remote-scope, absolute-unlock,
daily-cap, auth-failure lockout, lock, timeout, idle, audit,
activity, notification, and dialog bullets in section 5. Disabled
config opens no port. Wrong token does not run a tool and does not
start the helper. A polling sequence does not extend the 8-hour
stamp. A default-list `mail_trash` of a message already in Trash
does not call Proton. Unix socket tests still pass, including
`mail_draft_delete` and a `mail_trash` of a message already in
Trash, which keep today's local behavior.

### 4. Document the door in the security model

**Scope.** Docs only, after 3. Update `docs/security.md` with the
delta in section 4, including the absolute unlock lifetime, the
allowlist and the prompt-injection reason, the Grok Bot account as
a trust boundary with passkey or 2FA required, the Tailscale admin
console (disable Funnel, or disable the node) as the off-site kill
switch, the shared auth-failure lockout as accepted, the daily
read cap, screen lock left off as an accepted risk with a doctor
warning, and always-on Funnel as an accepted risk controlled by
the token, the auth-failure limit, the caps, and the audit log.
Say that remote `mail_trash` is recoverable only and refuses a
message already in Trash, and that permanent delete and
`mail_draft_delete` stay off the remote list. Update
`docs/configuration.md`, `docs/cli-reference.md`, and
`docs/architecture.md` so they no longer say the daemon never
listens on a network port: it listens on loopback only when this is
enabled, and the socket is unchanged. Include the turn-on steps.
Adjust the README "never a network port" line the same way. Do not
weaken the write-approval or lock wording. The owner decisions are
decided; the shipped docs state those values.

**Acceptance.** A reader of `docs/security.md` can see the new read
risk, the 8-hour stamp, screen lock off and always-on Funnel as
accepted risks, the tunnel-termination risk, the off-site kill
switch, the remote trash refusal, and the Grok account boundary
without opening this plan. The commands in section 2 match the CLI
reference, including clipboard show/rotate and `http activity`. No
code change beyond comments that those docs require.
