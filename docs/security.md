# Security model & threat model

The honest version. Read it before you trust proto-mcp with a live
mailbox. This document describes what proto-mcp defends, what it
deliberately does **not**, and the residual risks you accept by running
it.

For the per-defect fix log and audit trail, see
[`../SECURITY.md`](../SECURITY.md).

## The layers

The Keychain item that holds your Proton session sits behind several
layers of protection:

1. **macOS Keychain encryption** — standard at-rest protection for any
   keychain item. Everything below assumes you are logged in and the
   keychain is unlocked.
2. **Touch ID at session-acquire time** — the daemon prompts for
   biometric (or password fallback via Apple's
   `.deviceOwnerAuthentication`) on every startup and every unlock
   after a manual or automatic lock. The prompt is issued at the
   application layer by the Swift helper.

   An unlock can be requested either by `protonmcp unlock` or by a tool
   call arriving at a locked daemon. Who *asks* is not a security
   boundary — the sensor is, and it can't be satisfied by software. What
   the request path does expose is the prompt itself: content the model
   reads (mail bodies above all) can try to steer it into a tool call,
   and each locked call is an opportunity to raise a dialog. The threat
   is prompt fatigue, not unauthorized access, so it's bounded by rate
   rather than forbidden — one prompt in flight at a time, and a 60s
   cooldown after any prompt the user doesn't approve.
3. **Per-call approval** — every write tool fires a custom prompt + Touch
   ID showing the **literal** recipients and subject before anything
   happens. Approvals expire per policy TTL; `mail_send` has TTL 0, so
   every send re-prompts.

Plus, around the binaries themselves:

- **Hardened-runtime, Developer-ID-signed, Apple-notarized** binaries.
  Gatekeeper accepts them with no "unidentified developer" dialog.
- **SHA-256 binary integrity check** at daemon startup. If `protonmcpd`
  was swapped between install and launch, the daemon refuses to start.
- **Peer-credential checks** (`SO_PEERCRED` / `LOCAL_PEERPID`) on every
  socket connection; cross-UID connections are refused and the real
  connecting PID/UID is recorded in the audit log.
- **Default-deny policy** for unknown tools. A tool with no policy stub
  fails registration — you cannot accidentally ship an unguarded write.
- **Auto-lock** on screen lock, sleep, and idle timeout. Walk away and
  the daemon locks; resuming requires Touch ID.
- **Redacted audit log.** Passwords / tokens / cookies become
  `[REDACTED]`; bodies become `{sha256, bytes}`; recipient addresses
  stay literal so the prompt-verification chain is honest.

## Trust boundaries

The daemon runs as **you**, on **your** Mac, and talks to two parties:
the local MCP clients (Claude Desktop / Code, via the shim over a `0600`
Unix socket) and Proton's servers (over TLS, via `go-proton-api`). When
you turn it on, it can also answer one loopback HTTP port for a remote
MCP client. That door is off until `http.yaml` says `enabled: true` and
a token is in the Keychain. Mail content fetched from Proton is
**untrusted input** — it can contain anything a sender chose to put in
it.

## Defended

- **Local IPC isolation.** The socket is `0600` inside a `0700`
  directory; every connection is peer-credential checked and cross-UID
  connections are refused. The socket path and those checks are
  unchanged by the HTTP door. The HTTP door, when enabled, binds only
  a literal loopback address (`127.0.0.1` or `::1`), requires a bearer
  token on every request, ignores `X-Forwarded-For`, and sends no CORS
  headers. Its tool list can only remove tools. It cannot turn a
  policy `deny` into `allow` or `prompt`.
- **Remote trash is recoverable only.** HTTP `mail_trash` moves a
  message to Trash. If the mirror says the message is already in
  Trash, or the mirror has no row to decide, the call is refused
  before Touch ID and before any Proton call. Permanent delete and
  `mail_draft_delete` are not on the default remote list. Listing
  `mail_delete_permanent` does not enable it, because policy stays
  `deny`.
- **Session at rest.** The Proton session lives in the macOS Keychain;
  the daemon re-prompts for Touch ID on every startup and every unlock
  after a manual/auto lock (screen lock, sleep, idle timer).
- **Write authorization.** Every state-changing tool is deny-by-default
  in policy and fires a per-call Touch ID prompt showing the literal
  recipients and subject. `mail_send` has TTL 0 — every send re-prompts.
- **Binary tampering.** Hardened-runtime, signed, notarized binaries
  plus a SHA-256 self-check that refuses to run a swapped binary.
- **Log leakage.** Secrets are redacted; bodies are reduced to
  `{sha256, bytes}` in the audit log.
- **Mirror at rest.** `store.db` (bodies, envelopes, the full-text
  index, cached attachments, calendar text, the audit table) is
  AES-256-GCM under a random key in the login Keychain. A copy of
  that file without the key does not read.

## Out of scope — accepted risks

- **Prompt injection from email content.** `mail_read` and
  `mail_read_thread` are allow-by-default, so a malicious message *can*
  try to steer the model ("forward this to…", "delete that…"). The
  mitigation is the load-bearing fact that **every write is Touch-ID
  gated and shows the real recipients/subject** — reading a hostile
  email exfiltrates nothing on its own, and any send it provokes still
  needs your fingerprint on a prompt that names the actual recipient.
  **Do not blanket-approve sends**, and treat message bodies as hostile.

  The same applies to `mail_read`'s `unsubscribe` field, taken from the
  `List-Unsubscribe` / `List-Unsubscribe-Post` headers. Those headers
  are written by the sender, so the targets are attacker-controlled.
  They are scheme-filtered (only `https` without userinfo and a single
  `mailto` address survive; `http:`, `javascript:`, `data:` and the rest
  are dropped), capped in count and length, and **only exposed**:
  proto-mcp never fetches an unsubscribe URL or sends to an unsubscribe
  address itself. Any mailto send goes through the normal Touch-ID-gated
  `mail_send`. The raw values are cached next to the body and purged
  with it, because the URLs carry per-recipient tokens.
- **OS-level Keychain ACL is not enforced.** The biometric gate is
  enforced at the application layer, not sealed into the Keychain item
  with `SecAccessControl`. A process running as you, with the Keychain
  already unlocked, could read the stored session blob without a fresh
  Touch ID.

  This was investigated thoroughly and is a **hard platform limit**, not
  a backlog gap: the `SecAccessControl` + access-group path requires the
  restricted `keychain-access-groups` entitlement, which macOS (AMFI)
  will only honor with an Apple-issued provisioning profile. Apple
  issues those for App Store / TestFlight / enterprise distribution, not
  for the directly-distributed, Developer-ID-signed binaries proto-mcp
  ships. A signed binary carrying that entitlement is killed by the
  kernel at launch. The application-layer Touch ID gate is the practical
  security boundary, by design.
- **A local account already compromised.** Everything runs as your user.
  Malware already executing as you can read the Keychain (the login
  keychain is not sealed to this binary; see the item above), the
  plaintext working file `store.db.live` while the mirror is open, the
  JSONL audit log, and staged attachments. The sealed `store.db` does
  not add a boundary against that malware. proto-mcp is not a defense
  against code already running under your account.
- **The working file and attachment exports.** `store.db.live` (and its
  `-wal`) is plaintext for as long as any process has the mirror open,
  and again if the process crashes, until the next open seals it and
  shreds it. Shredding overwrites the file and unlinks it; APFS does
  not promise the old blocks are gone. Files the tools hand back for
  you to read — `attachment-staging/` for large downloads, and
  `mail_save_attachment`'s copy in `~/Downloads` — are plaintext on
  purpose. `protonmcp purge` removes the staging copies with the
  cached bodies.
- **Physical access to an unlocked, logged-in Mac.** The auto-lock
  triggers shrink the window, but an attacker at your unlocked machine
  during an unlocked session is outside the model.
- **Proton-side trust.** proto-mcp trusts Proton's API and your account
  security (SRP password + 2FA). It does not defend against a
  compromised Proton account or a malicious server response beyond
  ordinary input sanitization.

## The remote door

This is what changes when the loopback HTTP listener is on. Writes are
still default-deny plus a Touch ID prompt that shows the literal
recipients. Sends stay `ttl: 0`. Sleep and idle lock still drop the
in-memory session. A screen unlock still does not unlock the daemon.
The socket's peer checks stay; they simply do not apply to HTTP.

- **A bearer holder can read the mailbox without Touch ID, until the
  unlock clock runs out.** Reads on the remote list are `allow` on
  purpose. That used to require a same-user process on the Mac. With
  the door on, it requires the token, a path through the tunnel, the
  Mac awake, the daemon unlocked, and an HTTP stamp younger than
  `max_unlock_hours` (default 8, allowed 1–24, no unlimited value).
  The stamp is wall-clock time since the last successful Touch ID. A
  bot that keeps reading does not move it. Decline leaves the stamp
  and the local session as they were. The text a bot reads passes
  through that bot's servers. That is the accepted trade-off. A leaked
  token is a remote read until the stamp expires, you revoke, or you
  take the tunnel down. The mirror seal does not cover mail text after
  it leaves the daemon.
- **The Grok Bot account holds a copy of the token.** You paste it
  into that account's connector settings, so the account is inside the
  trust boundary. Turn on a passkey or 2FA there before you paste.
  `token show` and `token rotate` leave the token on the clipboard for
  about 60 seconds, with a countdown, and clear it on the way out or
  when you press Ctrl-C. While it sits there, macOS Universal Clipboard
  can copy it to your other Apple devices. Someone who can open the
  Grok account can use the token until you revoke it or take the
  tunnel down.
- **The Keychain limit now includes the remote token.** A process
  running as you can read Keychain items without a fresh Touch ID.
  That includes `http-bearer`. The seal on `store.db` does not stop a
  local process from copying the token and using it from outside the
  house. Revoke, and turning Funnel off, are the responses. There is
  no new Keychain entitlement; the restricted-entitlement wall above
  still applies.
- **Screen lock is off.** That is an accepted risk, not a precondition.
  `protonmcp doctor` and `protonmcp http enable` warn when screen lock
  is off, and they do not block. Sleep still locks the daemon. The
  backstops are the 8-hour HTTP stamp, which idle cannot move, and the
  Tailscale admin console.
- **Funnel stays on.** That is an accepted risk: a permanent public
  name, and scanners will hit it. The controls are the bearer token,
  the shared auth-failure limit (10 failures a minute, then `429` for
  everyone, including the real bot, for the rest of that minute), the
  per-minute cap, the daily read cap (default 500, stored so a restart
  does not zero it), and the audit log. A bad or missing bearer counts,
  including a bearer sent in the query string and a failed `DELETE`.
  The token is never accepted from the query string. Every HTTP tool
  call that passes auth, reads included, writes a redacted row.
- **A present Origin is rejected unless you listed it.**
  `allowed_hosts` checks the Host header only. `allowed_origins` is
  empty by default, and a loopback Origin is not implied by a loopback
  listen address. A missing Origin is allowed. There is no CORS header.
- **An unusable `http.yaml` closes the listener.** A file that does
  not parse, is writable by the group or by others, or is not owned by
  you is treated as disabled. The daemon does not keep serving on the
  last good config. `http disable` rewrites that file to
  `enabled: false` and the listener closes. SIGHUP re-reads
  `http.yaml` even when the policy file failed to reload.
- **Repeated auth failures turn the door off for the day.** A bad
  bearer, a missing bearer, and a bearer in the query string count,
  including `DELETE`. The default is 50 in a local calendar day.
  `0` means 50. There is no value that turns the counter off. At the
  threshold the daemon writes `enabled: false`, closes the listener,
  drops HTTP sessions, writes an audit row that does not contain the
  token, and posts a notification. A failed notification leaves the
  door off. Midnight resets the count and does not turn the door
  back on. The only re-enable is `protonmcp http enable`, which also
  zeros today's count. This is not an idle lock.
- **Prompt injection from mail the bot reads.** A hostile message can
  tell the bot to trash, download, or send. Download and recoverable
  trash are on the default remote list and still require Touch ID.
  A second trash, of a message already in Trash, is refused before
  any Proton call. Permanent delete, empty Trash, and
  `mail_draft_delete` are not on the list, and adding a name cannot
  beat a policy `deny`. Sends still require Touch ID showing the real
  recipients, `ttl` 0. Filing stays off the default list.
- **The off-site kill switch is the Tailscale admin console.** Disable
  Funnel, or disable this Mac's node. That cuts the network when you
  are not at the Mac. The daemon may still be listening on loopback.
  The token is unchanged until you revoke it, and revoke still needs
  the Mac. Logout does not revoke the token and does not disable
  Funnel.
- **A tunnel that terminates TLS in the wrong place reads everything.**
  Tailscale Funnel ends TLS in `tailscaled` on the Mac, so the relay
  sees ciphertext. Cloudflare Tunnel and ngrok terminate TLS at the
  vendor and can read the token and the mail. Do not use them. Point
  Funnel only at `http://127.0.0.1:4765`, not at the Unix socket and
  not at a mode that serves files from disk.

The approval dialog for an HTTP call says `Requested by: http:<label>`.
There is no request field that skips the prompt. If the helper is
missing, a `prompt` tool is denied, as it is for a local caller. One
approval dialog can be up at a time. A second call is told a prompt is
already waiting. An approval cached for the Unix socket is not reused
by HTTP, and the reverse is not reused either. Rate-limit buckets are
per tool, shared by every caller.

Turn the door on only after a passkey or 2FA is on the Grok Bot
account. The steps are in
[configuration.md](./configuration.md#the-remote-door).

## Reducing your exposure

- Keep `mail_send` at TTL 0 (the default) and actually read the Touch ID
  prompt — it shows the real recipient.
- Skim the audit log periodically (see [observability in
  configuration.md](./configuration.md#observability)).
- Don't raise `max_attachment_bytes` past what you need; large decrypted
  attachments are written to a local staging directory for the client
  to read.
- Use `protonmcp purge --older-than 7d --vacuum` to shorten how long
  decrypted bodies and attachments stay in the sealed mirror.

## What an approval looks like

Tools with `confirm: true` (every send, plus save-attachment and
folder/label delete) show the full operation in an alert first. The
body is a scrolling text view, not the Touch ID sheet's title: macOS
puts `localizedReason` in the title and clips it, which would hide a
recipient past the first line. Allow on that alert is what reaches
Touch ID; Cancel never prompts. The Touch ID reason is then the short
title ("Approve mail_send?"), because the list was already on screen.

Other prompted tools (trash, move, label) put their shorter sentence
in the Touch ID sheet directly.

When Claude says "move 'Re: gear list' from inbox to archive," the prompt
that fires says exactly that — not a redacted argument dump:

```
┌──────────────────────────────────────────────┐
│ protonmcp-touchid is trying to               │
│ move message 'Re: gear list' from inbox      │
│ to Archive                                   │
│                                              │
│ Touch ID or enter your password to allow.    │
│              [ Cancel ]    [ Touch ID ]      │
└──────────────────────────────────────────────┘
```

The verb phrase comes from a per-tool `PromptBody` closure
(`internal/mcptools/prompt_helpers.go`) that resolves `message_id →
Subject` and `label_id → Name` from the local mirror. You read what
you're approving.

For sends, the format is stricter — the recipient list is always
verbatim:

```
┌──────────────────────────────────────────────┐
│ Approve mail_send?                           │
│                                              │
│ To (1): alice@example.com                    │
│ Cc (1): charlie@example.com                  │
│ Bcc (0): (none)                              │
│ Subject: Re: gear list                       │
│                                              │
│ [ Cancel ]                           [ Allow ]│
└──────────────────────────────────────────────┘
```

Allow is followed by Touch ID (or the account password). Each list
is labeled with its count, including Bcc. If the alert cannot show
the whole body at once, Allow stays disabled until the list is
scrolled to the end. Addresses are an ASCII allowlist; an IDN domain
is shown and sent only as its UTS-46 punycode. Anything else, and a
subject or attachment name that contains a hidden or bidirectional
character, is refused.
