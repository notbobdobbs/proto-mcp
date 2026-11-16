# Configuration, locking & observability

## Policy

Every tool's behavior is governed by a YAML policy. Defaults live in
[`../internal/policy/default.yaml`](../internal/policy/default.yaml)
(embedded into the binary). Override per-tool by creating
`~/Library/Application Support/protonmcp/policy.yaml`:

```yaml
tools:
  mail_send:
    decision: prompt
    confirm: true
    rate_limit: 5/hour                       # cap LLM-driven sends
    allowed_recipients: ["@mydomain.com"]    # restrict to one domain
  mail_trash:
    decision: prompt                         # reversible; mail_move puts it back

# Auto-lock idle timer
idle_lock_minutes: 30                        # lock if no tool call for 30 min (0 = disabled)
```

Each tool's `decision` is one of `allow`, `prompt`, or `deny`. Writes are
`prompt` by default; reads are `allow`; anything unknown is `deny`. The
default-deny stance is enforced at registration — a tool with no policy
entry won't load, so you can't accidentally ship an unguarded write.

Reload without restarting:

```sh
protonmcp policy reload                 # SIGHUP every running daemon / serve-stdio
protonmcp policy show                   # print the merged effective policy
protonmcp policy validate ./my-policy.yaml
```

Rate-limit buckets persist to SQLite, so a daemon restart doesn't reset
the per-hour cap. The bucket is the tool name only. Two local clients,
and the HTTP door, share the cap you configured. Older rows keyed by
process id are left in the database and are not read.

## Locking

```sh
protonmcp lock      # daemon zeros its in-memory session
protonmcp unlock    # Touch ID prompt re-acquires the session from the Keychain
```

The daemon also auto-locks on:

- macOS screen lock (`com.apple.screenIsLocked`)
- system sleep (`NSWorkspaceWillSleepNotification`)
- idle timeout (`idle_lock_minutes`; default `0` = disabled)

Unlocking your Mac's screen does **not** unlock the daemon — handing the
session keys back needs Touch ID, and a screen unlock isn't that.

While locked, a tool call raises the Touch ID prompt itself and proceeds
once you approve, so you don't have to reach for a terminal. The model
can ask for the unlock; only the sensor grants it. Prompts are bounded:
one at a time, and after a prompt you don't approve, no further ones for
60 seconds. `protonmcp unlock` bypasses that cooldown.

If the prompt is declined or suppressed, the call returns `daemon is
locked (<reason>); ...` with the reason it couldn't proceed. No audit row
is written for the blocked attempt (it's logged at WARN instead).

`protonmcp doctor` reports lock state, so a locked daemon shows up as a
`warn` line rather than looking healthy.

## The remote door

The daemon can open a second door for a remote MCP client. It listens
on loopback only, and only when both of these are true: `http.yaml`
has `enabled: true`, and the Keychain holds a token. Missing either
one means no listener. `serve-stdio` does not grow a listener. The
Unix socket is unchanged.

The file is `~/Library/Application Support/protonmcp/http.yaml`, mode
`0600`. It is not `policy.yaml`. Editing tool rules cannot open the
port. An absent file means off.

```yaml
enabled: false
listen: 127.0.0.1:4765
caller_label: remote
allowed_hosts:
  - 127.0.0.1:4765
  - localhost:4765
max_requests_per_minute: 60    # 0 means 60, never unlimited; hard ceiling 600
max_remote_reads_per_day: 500  # 0 means 500, never unlimited; hard ceiling 5000
max_unlock_hours: 8            # 0 means 8; allowed 1–24; no unlimited value
# remote_tools omitted means the built-in default, not every tool.
```

`listen` must be `127.0.0.1` or `::1` with an explicit port. `0.0.0.0`,
a LAN address, an empty host, and the name `localhost` are refused.
Add the tunnel's public hostname to `allowed_hosts` when you turn the
tunnel on. A Host or Origin that is not on the list is rejected before
any tool runs. A missing Origin is allowed. The Origin value `null` is
rejected.

Omitted or empty `remote_tools` means the built-in default, not every
tool. The default is search, read, draft, send, attachment download,
and recoverable trash: `account_whoami`, `mail_list`, `mail_search`,
`mail_read`, `mail_read_thread`, `mail_list_attachments`, `mail_sync`,
`labels_list`, `folders_list`, `calendar_list`, `calendar_events`,
`calendar_read_event`, `mail_draft_list`, `mail_draft_create`,
`mail_draft_update`, `mail_send`, `mail_send_draft`, `mail_reply`,
`mail_reply_all`, `mail_forward`, `mail_download_attachment`,
`mail_trash`. Setting the list replaces that default. `mail_draft_delete`
and `mail_delete_permanent` are not on it. `*` or `all`, a number below
0, `max_unlock_hours` above 24, or a rate above its hard ceiling makes
the file unusable: the previous good file stays, and a first load does
not enable the listener.

`protonmcp policy reload` (SIGHUP) also re-reads `http.yaml` and opens
or closes the listener. Each request reads the token from the Keychain,
so revoke is immediate.

```sh
protonmcp http token rotate    # new token on the clipboard for about 60 seconds; not printed
protonmcp http token show      # same clipboard copy, only after Touch ID; decline copies nothing
protonmcp http token revoke    # delete the token; logout does not do this
protonmcp http enable          # refuses without a token; warns if screen lock is off, and still enables
protonmcp http disable         # stop listening; the socket keeps working
protonmcp http status          # enabled, listen address, whether a token exists; never the token
protonmcp http activity        # remote call counts; --ids also prints message ids; never a body
```

`token rotate` and `token show` clear the clipboard about 60 seconds
later only if it still holds that token. Neither command takes the
token as an argument. A Mac is required for show and rotate.

Screen lock left off is an accepted risk. `http enable` and `doctor`
warn. They do not block, and the warning does not fail `doctor`.

### Turn it on

1. Leave macOS screen lock off. That is the accepted setting. `protonmcp doctor` and `protonmcp http enable` warn. They do not block. The backstops are the 8-hour HTTP unlock clock and the Tailscale admin console.
2. On the Grok Bot account, turn on a passkey or 2FA. The token will live in that account's connector settings.
3. `protonmcp http token rotate`. The token is on the clipboard for about 60 seconds. Paste it into the connector header `Authorization: Bearer <token>`.
4. `protonmcp http enable`. It refuses without a token. It warns if screen lock is off, and it still enables.
5. Start Tailscale Funnel to `http://127.0.0.1:4765` and leave it on. Add that hostname to `allowed_hosts`. Scanners will hit the public name. The kill switch, when you need it, is the Tailscale admin console: disable Funnel, or disable the node.
6. Leave `remote_tools` unset. The default includes `mail_download_attachment` and `mail_trash`. Adding `mail_draft_delete` means listing the default names plus that tool. Listing `mail_delete_permanent` does not enable it.

Funnel stays on. That is an accepted risk. The controls are the token, the auth-failure limit, the per-minute and daily caps, and the audit log. Do not point the tunnel at the Unix socket. Cloudflare Tunnel and ngrok can read the token and the mail because they terminate TLS; do not use them. Tailscale Funnel ends TLS on your Mac.

## Observability

Two log destinations, both auto-rotated at 50 MB × 10 generations:

```sh
# Audit log — one JSON object per completed tool call
tail -f ~/Library/Application\ Support/protonmcp/audit.log

# Daemon slog output
tail -f ~/Library/Logs/protonmcp/daemon.log
```

Or query the mirror's working file while the daemon (or a CLI
command) has it open. `store.db` itself is sealed and `sqlite3` will
not open it; see [at-rest data](#at-rest-data--purging).

```sh
sqlite3 ~/Library/Application\ Support/protonmcp/store.db.live \
  'SELECT tool, transport, caller_label, outcome, policy_decision, duration_ms
     FROM audit_log
    ORDER BY id DESC LIMIT 20;'
```

An HTTP row has `transport=http`, the configured label, and the name
the client claimed at initialize. That name is recorded and is not
trusted. A socket row has `transport=unix` and an empty claimed client.
Args still keep `message_id` literal and store a body only as
`{sha256, bytes}`. `protonmcp http activity` prints the remote counts
and does not print a body. Once a day the daemon can post a
notification of those counts, and it posts nothing when the day had
no remote calls.

Every audit row carries: tool name, caller PID + UID + binary, policy
decision, outcome (`ok` / `denied` / `error`), approval source (`touchid`
/ `cached` / `policy`), error message (if any), duration in ms, and
redacted arguments.

## At-rest data & purging

When Claude reads a message, the decrypted body is cached so repeat
reads are instant and offline. The cache lives in `store.db`, which is
sealed with AES-256-GCM under a random key in the macOS Keychain
(`zone.dort.protonmcp` / `store-key`). The same seal covers envelopes,
the full-text index, cached attachment bytes, calendar text, and the
audit table. `sqlite3 store.db` cannot open that file.

While any process has the mirror open, SQLite runs on a plaintext
working file `store.db.live` (mode `0600`). The last close seals it
back over `store.db` and shreds the working file, its `-wal` / `-shm`,
and a crash leftover is sealed again on the next open. An existing
plaintext `store.db` from an older build is sealed on first open and
the old file is overwritten with random bytes and removed.

```sh
protonmcp purge --older-than 7d         # drop cached bodies sooner
protonmcp purge --vacuum                # reclaim the freed pages
```

`secure_delete=on` still zeroes deleted cells in the working file.
Large attachment exports (`attachment-staging/`) stay plaintext for
the MCP client to read and are swept by the same purge. See
[security.md](./security.md) for what the seal does not cover.
