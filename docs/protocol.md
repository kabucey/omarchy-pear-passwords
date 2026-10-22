# Pear Passwords 2 daemon protocol

Status: **frozen** (protocol version 2). This is the contract between `pear-passwordsd` and its
four kinds of client: the Pear window (`ui`), the clipboard writer (`clip`), the v1 importer
(`migrate`) and the browser autofill host (`autofill`). The same values in code are in
`backend/icp/daemon/protocol.py` and `backend/icp/daemon/paths.py`;
`backend/tests/test_protocol_contract.py` fails if this document and that module disagree on
an op, an event or an error code. The daemon and every client change together with this
document.

The browser-facing side of autofill (native messaging between an extension and
`pear-autofill-host`) is specified separately in `docs/autofill-protocol.md`. This file
covers only what that host says to the daemon.

---

## 1. Transport and framing

- Socket: `/run/pear-passwords/client.sock`, `SOCK_STREAM`, owned `pear-passwords:pear-client`,
  mode 0660. Only a process whose effective gid is `pear-client` can connect, and only
  `pear-exec` produces one.
- Encoding: UTF-8 JSON, one object per line, terminated by `\n`. No other whitespace rules.
  Every line is a JSON object; anything else is `bad-request`.
- Size limits are asymmetric:
  - client to daemon: at most **64 KiB** per line including the newline. A longer line gets
    `{"rid":null,"error":"too-large"}` and the connection is closed.
  - daemon to client: at most **8 MiB** per line. The account list for 554 entries is about
    150 KiB, so every client must accept long lines.
- Requests: `{"op": "<name>", "rid": <int>, ...fields}`. `rid` is a client-chosen integer
  from 0 to 2^53-1 and is echoed in the reply. Rids need not be unique across the life of a
  connection but must be unique among requests still awaiting a reply.
- Replies: `{"rid": <int>, ...payload}` on success, `{"rid": <int>, "error": "<code>", ...}`
  on failure. Every request gets exactly one reply, except `signin`, which also gets a stream
  of events carrying its rid before its reply (section 9).
- Events: `{"event": "<name>", ...}` with no `rid`, except the sign-in stream.
- Unknown extra fields in a request are ignored. Missing or mistyped required fields are
  `bad-request`. Unknown `op` is `unknown-op`. An op not allowed for the connection's role is
  `forbidden`.
- Concurrency: requests on one connection are handled concurrently and replies may arrive out
  of order. At most **16** requests may await a reply per connection; the 17th gets
  `too-many`. Ordering guarantee: an event caused by a request (for example `synced` after
  `unlock`) is sent after that request's reply.
- Timestamps are unix seconds as JSON numbers (may be fractional). History dates are ISO 8601
  UTC strings (`"2026-10-08T12:34:56Z"`).

## 2. Connection lifecycle

### 2.1 Peer verification (before any byte is read)

On every accept the daemon checks, and closes the connection silently on any failure:

1. `SO_PEERCRED`: `gid == pear-client`, `uid >= 1000`.
2. `SO_PEERPIDFD` (option 77): a pidfd held for the life of the connection.
3. `/proc/<pid>/status`: `Gid:` real = the user's gid, effective = `pear-client`; `Uid:`
   real = effective = uid. `/proc/<pid>/stat` gives the start time. Then
   `pidfd_send_signal(pidfd, 0)` confirms the pid was not recycled.

### 2.2 hello

The first line must be `hello` and must arrive within **5 s** of connecting; otherwise
`{"rid":null,"error":"hello-required"}` and close.

Request:

```json
{"op":"hello","rid":0,"role":"ui","proto":2}
{"op":"hello","rid":0,"role":"clip","proto":2,"ticket":"<43 chars base64url>"}
{"op":"hello","rid":0,"role":"migrate","proto":2,"ticket":"<43 chars base64url>"}
{"op":"hello","rid":0,"role":"autofill","proto":2}
```

`proto` other than 2: `{"rid":0,"error":"proto","proto":2}` and close. Unknown role: close
without a reply.

Role rules:

| role | rule |
|---|---|
| `ui` | At most one per uid. A second `ui` hello gets `{"rid":0,"error":"already-running"}` and is closed; the existing UI gets `{"event":"focus"}`. |
| `clip`, `migrate` | `ticket` required. It must be live (10 s), unused, issued on this uid's UI connection for this role, and the client's `PPid` must equal that UI's pid with a matching UI start time. Otherwise `{"rid":0,"error":"bad-ticket"}` and close. The ticket is consumed by the hello, success or not. More than 5 bad tickets per uid per minute: further `clip`/`migrate` hellos for that uid are refused with `bad-ticket` for the rest of the minute. |
| `autofill` | Refused with `{"rid":0,"error":"forbidden"}` and closed until the user turns autofill on in the window (`autofill-enable`, section 6). No ticket, no parent binding: `pear-exec autofill` runs for any program of the user, so this switch, not the browser manifest, is the opt-in. At most **4** live autofill connections per uid; the 5th gets `{"rid":0,"error":"too-many"}` and is closed. |

Replies:

`ui`:

```json
{"rid":0,"proto":2,"version":"2.0.0","state":"locked","signed_in":true,
 "sealed_with":"host","synced_at":null,"needs_login":null,
 "settings":{"grant_s":120,"idle_lock_s":300,"clip_timeout_s":30,"window_mode":"floating"},
 "migration_pending":false,"autofill":{"enabled":false,"hosts":0},
 "old_copy":{"dir":"/home/u/.config/icp.v1-backup-20261008","migrated_at":1791450000.0}}
```

- `state`: one of `empty`, `locked`, `unlocked`, `tpm-missing`, `tpm-cleared`, `damaged`
  (section 4). A fresh `ui` hello is never `unlocked`, because the previous UI's EOF locked
  the uid.
- `signed_in`: whether an iCloud session is stored (known without keys).
- `sealed_with`: `"host"`, `"host+tpm2"`, or `null` when `empty`.
- `synced_at`, `needs_login`: `null` while locked (they live under the metadata key).
- `old_copy`: the v1 backup recorded by a migration, or `null`.
- `autofill`: whether browser autofill is turned on, and how many autofill hosts are connected.
- `migration_pending`: an earlier `migrate-begin` created keys but its import never committed
  (the window was closed at the passphrase step). The window then offers the move again; a
  `signin` with mode `login` is refused with `migration-pending` until it has, or until the
  record is dropped: `migrate-abandon` (no dialog; the window sends it when `vault.enc` is
  confirmed missing - FileNotFound, not any load failure - or "Start fresh instead" is
  chosen) or `reset` (`.manage`).

`clip` (after the ticket is checked):

```json
{"rid":0,"proto":2,"version":"2.0.0","purpose":"copy"}
```

`migrate`:

```json
{"rid":0,"proto":2,"version":"2.0.0","purpose":"import"}
{"rid":0,"proto":2,"version":"2.0.0","purpose":"purge",
 "files":[{"name":"vault.enc","sha256":"<hex>"}],"dir":"/home/u/.config/icp.v1-backup-20261008"}
```

`autofill`:

```json
{"rid":0,"proto":2,"version":"2.0.0","state":"locked"}
```

with `state` one of `locked`, `unlocked`, `unavailable` only. `unavailable` covers `empty`,
`tpm-missing`, `tpm-cleared` and `damaged`; nothing else about the store is disclosed.

### 2.3 Tickets

- 32 random bytes, sent as unpadded base64url (43 characters).
- Issued only on a `ui` connection by `copy` (role `clip`), `migrate-begin` (role `migrate`,
  purpose `import`) and `purge-old-copy` (role `migrate`, purpose `purge`).
- Bound to: uid, the issuing UI connection, the role, the purpose, and for `copy` the
  `(id, field)` and the value snapshot taken at issue time.
- Single use, **10 s** TTL from issue to hello. All of a uid's tickets are revoked by any lock.
- The UI passes a ticket to its child **on stdin only** (section 10), never in argv or the
  environment.

### 2.4 Closing

- EOF on the `ui` connection locks the uid (section 4.2), cancels its pending dialogs and
  withdraws every live `clip` and `migrate` connection of the uid (`{"event":"withdraw"}`,
  then close).
- EOF on any connection cancels its pending dialogs (`CancelCheckAuthorization`).
- The daemon closes a connection whose client stops reading (send buffer over 16 MiB).

## 3. Shared shapes

### 3.1 Meta (what tier 1 releases)

```json
{"id":"<opaque>","title":"GitHub","domain":"github.com","sites":["gist.github.com"],
 "username":"me@example.com","nickname":"","apple_title":"GitHub","aliases":[],
 "has_totp":true,"has_notes":false,"mdat":1791450000.0,"history_count":2,
 "primary":"GitHub","secondary":"me@example.com","no_site":false,"is_wifi":false,
 "ambiguous":false,"tags":["work","finance"],"has_passkey":false,"kind":"login",
 "has_password":true,"recently_deleted":false}
```

- The first twelve fields and the last five are `vstore.Meta`. `id` is opaque to clients: at
  most 128 characters of `[A-Za-z0-9._:-]`, stable for the same keychain item across syncs.
- `tags` are the tags on the final `Tags: #a #b` line of the entry's notes (canonical: NFC,
  lower case, at most 16, first-seen order), and `has_notes` says whether the notes **body**
  (the notes without that line) has anything in it. The grammar: the whole last line must be
  `[WS] Tags: WS1 #tag *(WS1 #tag) [WS]`, "Tags" in any case, each tag 1 to 32 Unicode
  letters, marks, digits, `_` or `-`; any other last line is body text.
- `kind` is `passkey` for a row that is only a passkey (`has_password` false); `has_passkey`
  marks a login that also has one. `recently_deleted` marks a copy in Apple's Recently Deleted
  (an access group ending in `-recently-deleted`); it never merges with, or stands in for, the
  live entry. Passkey-only rows and Recently Deleted copies are in the list only while their
  feature is on (`features`, section 6.10), and `has_passkey` is false while `passkeys` is
  off. Both are read-only: `set` on one is `invalid` with `field:"id"`, and autofill never
  offers one.
- `primary`, `secondary`, `no_site`, `is_wifi`, `ambiguous` are display fields the daemon
  derives exactly as 1.3.2's `app-list` did (nickname, then Apple's title, then the derived
  title; Wi-Fi items are domain `AirPort`; `ambiguous` when two rows would look identical).
- Entries 1.3.2 hid as internal (Apple service records, HomeKit keys, ...) are omitted unless
  `unlock` was sent with `"all":true`.
- The list is sorted by `primary`, then `secondary`, case-insensitively.
- Meta never contains a password, notes text, a TOTP seed or code, or a pwmac, **except the
  tag line's tags**, which are list metadata like titles and usernames: anyone who passes the
  first dialog sees them.

### 3.2 Settings

```json
{"grant_s":120,"idle_lock_s":300,"clip_timeout_s":30,"window_mode":"floating"}
```

| key | default | allowed |
|---|---|---|
| `grant_s` | 120 | integer 0..600; 0 = a grant is used up by its first use |
| `idle_lock_s` | 300 (5 minutes) | 0, 300, 900, 1800 |
| `clip_timeout_s` | 30 | integer 5..60 |
| `window_mode` | `"floating"` | `"floating"` (960x640, centred) or `"regular"` (tiled like other windows); read from the hello reply before the window maps |

There is no `sync_lease_h`: 2.0 has no sync lease. A `set` naming any other key is
`{"error":"invalid","field":"<key>"}` and nothing is changed.

## 4. States, locking and sync

### 4.1 States

| state | meaning | how a UI leaves it |
|---|---|---|
| `empty` | no store for this uid | `migrate-begin` (v1 present) or `signin` (fresh) |
| `locked` | store present, no keys in memory | `unlock` |
| `unlocked` | tier 1 open on this uid's UI connection | any lock trigger |
| `tpm-missing` | sealed with host+tpm2 and no TPM now | turn PTT back on; no destructive action offered |
| `tpm-cleared` | a TPM is present but its SRK differs | `reset` |
| `damaged` | keys unseal but data does not authenticate | `reset` (files are kept) |

The seal states are discovered at `unlock` (unsealing is lazy) and are then reported by
`hello` until the store changes.

### 4.2 Lock triggers

Each of these wipes every key, subkey, grant, ticket and live clip offer of the uid, then
sends `{"event":"locked","reason":...}` to the UI if it is still connected:

| trigger | reason |
|---|---|
| `lock` op | `user` |
| UI connection EOF | (no event; the UI is gone) |
| logind `Lock` signal or `LockedHint=true` on any session of the uid | `screen-locked` |
| `PrepareForSleep(true)` (wiped before the delay inhibitor is released) | `sleep` |
| the uid's last session removed | `session-ended` |
| `idle_lock_s` seconds with no UI request | `idle` |
| `reset` | (no event: the window asked for it, and gets `{state:"empty"}`) |
| `signout` | `signout` |
| an unrecoverable daemon error for this uid | `error` |

After a lock nothing re-prompts until the UI sends `unlock` again.

### 4.3 Sync

Sync runs only for a uid whose tier 1 is unlocked: right after every successful `unlock`,
every 2 h (±60 s jitter) while unlocked, and on a `sync` op. It never prompts and never
unseals the entry key. Results reach the UI as `synced` or `sync-failed` events. There is no
lease: a locked uid does not sync.

## 5. Prompts (polkit)

| action | message | raised by |
|---|---|---|
| `io.github.dragosol.pearpasswords.unlock` | Unlock Pear Passwords to show your accounts | `unlock` |
| `io.github.dragosol.pearpasswords.manage` | Change Pear Passwords on this computer | `create`, `delete`, `signin`, `signout`, `migrate-begin`, `reset`, `purge-old-copy`, `clip-history-check`, `autofill-enable`, `tpm-move`, `features` (a change), `diag-items` |
| `io.github.dragosol.pearpasswords.autofill` | A browser extension asks to fill the password for $(account) on $(origin) | `autofill-fill` |
| `io.github.dragosol.pearpasswords.autofill-names` | A browser extension asks to see which accounts you have saved for $(origin) | `autofill-names` (only for a site not yet named) |

All four: `auth_self` for active local sessions, `no` for any and inactive, no `_keep`, owner
annotation `unix-user:pear-passwords`. No other op ever raises a dialog.

- Subject: `unix-process` with the connection's `pidfd` (and `uid`); fallback
  `{pid, start-time, uid}` if gate G2 fails. `AllowUserInteraction` is set only while
  handling one of the ops above.
- Details: `account` = `"<title> — <username>"` (nickname if set; domain when there is no
  title), `origin` = the origin's host (autofill only). Each value is reduced to printable
  characters with no control or bidi characters and cut to 64 characters.
- Outcomes and the codes they map to:

| polkit result | code | counted against the limit |
|---|---|---|
| authorized | (success) | no |
| challenge failed with `polkit.dismissed` | `dismissed` | yes |
| not authorized after a challenge | `denied` | yes |
| not authorized without a challenge (a policy `no`, an agent that died mid-dialog) | `denied` | no |
| no agent registered (G7), or polkitd/the bus unreachable | `no-agent` | no |
| polkitd refused the call itself (`NotAuthorized`, a bad subject) | `internal` | no |
| agent busy with another dialog | `busy` | no |
| cancelled by the daemon (EOF, `cancel`, lock) | `cancelled` | no |

- Rate limits, per uid and **bucket** (`ui` for the window's ops, `autofill` for the browser's):
  - one outstanding dialog per bucket: a second prompt-raising op gets `prompt-pending`;
  - at most **3 refused** (dismissed or denied) dialogs per rolling minute per bucket and
    action; the next op raising that action gets
    `{"error":"rate-limited","retry_after":<seconds>}` without a dialog. Approvals are not
    counted. Account grants never prompt and do not spend this budget.
- For `unlock` a refusal is a normal reply, not an error (section 6.1). For every other op it
  is `{"rid":n,"error":"<code>"}`.

## 6. UI ops (role `ui`)

Unless stated, ops that need tier 1 return `locked` when the uid is not unlocked, and ops that
name an `id` return `not-found` for an id with no live entry.

### 6.1 unlock

```json
{"op":"unlock","rid":1}
{"op":"unlock","rid":1,"all":true}
```

Raises `.unlock` (no dialog if already unlocked on this connection). Success:

```json
{"rid":1,"entries":[<Meta>...],"synced_at":1791450000.0,"needs_login":false,"tpm_move":false,
 "features":{"passkeys":false,"apple_deleted":false}}
```

then a background sync. `features` are the categories that wait for a check on a real
keychain (section 6.10); the window shows a category only when its flag is true. Refusal (a reply, not an error):

```json
{"rid":1,"locked":true,"reason":"dismissed"}
```

`reason` is `dismissed`, `denied`, `no-agent`, `busy`, `rate-limited` (with `retry_after`),
`empty`, `tpm-missing`, `tpm-cleared` or `damaged`. The seal reasons come from unsealing after
an approved dialog. Unlocking never moves the keys onto the TPM: `tpm_move` is true when a
usable TPM2 is present, the keys are host-sealed and nothing blocks TPM sealing, and the
window then offers the move as a button (`tpm-move`, section 6.9).

### 6.2 lock, release, cancel

```json
{"op":"lock","rid":2}                      -> {"rid":2,"locked":true}
{"op":"release","rid":3}                   -> {"rid":3,"released":true}
{"op":"cancel","rid":4,"target":1}         -> {"rid":4,"cancelled":true|false}
```

- `lock`: lock trigger `user` (section 4.2). Then also the `locked` event.
- `release`: drop the current grant (if any) and invalidate pending entry reads. The UI sends
  it whenever the selected account changes. Never an error.
- `cancel`: cancel the pending request with rid `target` on this connection if it is a
  prompt-raising op or `signin`; that request then replies `cancelled`. `cancelled:false` if
  nothing was pending under that rid.

### 6.3 grant

```json
{"op":"grant","rid":5,"id":"<id>"}
```

Needs tier 1 on the exact UI connection that authenticated at unlock. Never prompts.
Wipes any existing grant (one grant per uid), then opens that entry's temporary secret buffer.
A lock, release or newer grant during the read discards its result. Switching accounts and
reopening expired buffers reuse the same unlocked session. Success:

```json
{"rid":5,"id":"<id>","expires":1791450120.0,"grant_s":120,"single_use":false,
 "fields":["password","notes","code","history"]}
```

- `expires` is `null` and `single_use` is `true` when `grant_s` is 0: the first `reveal`,
  `totp`, `history`, `copy` of a secret field, or `set` on that id uses it up.
- `fields` lists what the entry has: `password` if `has_password` (not on a passkey-only
  row), `notes` if `has_notes` (a body that is not empty), `code` if `has_totp`, `history` if
  `history_count > 0`.
- When the grant ends the daemon zeroes the entry's buffer and sends
  `{"event":"grant-expired","id":"<id>"}` (also after `release`, a new `grant`, or single use).

### 6.4 Ops that need a grant on `id`

Each returns `no-grant` with no live grant on that id, `grant-expired` if it just ran out.

```json
{"op":"reveal","rid":6,"id":"<id>","field":"password"}
  -> {"rid":6,"id":"<id>","field":"password","value":"...","hide_after":20}
{"op":"totp","rid":7,"id":"<id>"}
  -> {"rid":7,"id":"<id>","code":"123456","valid_until":1791450030.0}
{"op":"history","rid":8,"id":"<id>"}
  -> {"rid":8,"id":"<id>","items":[{"date":"2026-09-01T10:00:00Z","value":"...","source":"apple"}]}
```

- `reveal` `field`: `password` or `notes` (else `invalid`). `notes` is the body: the tag line
  is not in it (it reaches the window as `tags`). The UI shows the value for at most
  `hide_after` seconds or until it loses focus.
- `totp`: `invalid` if the entry has no code. The seed never leaves the daemon.
- `history`: newest first; `source` is `apple` (Apple's own record) or `local` (a change this
  machine saw, including the older of two 1.x items for the same account, see 8 and 9.1),
  as the store labels each item.

### 6.5 copy

```json
{"op":"copy","rid":9,"id":"<id>","field":"password"}
  -> {"rid":9,"ticket":"<43 chars>","ttl":10}
```

- `field`: `username`, `domain` (tier 1 only, no grant), or `password`, `code`, `notes`
  (need a grant). `code` is computed at issue time; `notes` is the body, without the tag
  line.
- The value is snapshotted into the ticket. The UI then runs `pear-exec clip` and writes the
  ticket to its stdin (section 10.1). The outcome arrives later as the `clip` event.
- A new `copy` withdraws the uid's previous live clip offer (`withdraw` to that clip).

**copy-text**: Ctrl+C or the context menu's Copy on selected text in one of the window's secret
fields. The text goes through pear-clip like a `copy`, never onto the persistent clipboard.

```json
{"op":"copy-text","rid":26,"source":"notes-edit","id":"<id>","text":"<selected text>"}
  -> {"rid":26,"ticket":"<43 chars>","ttl":10}
{"op":"copy-text","rid":27,"source":"create-password","text":"<selected text>"}
```

- No dialog: the text is already in the window, so a prompt would protect nothing. Needs
  tier 1.
- `source` is one of a fixed list (else `invalid`, `field:"source"`): `notes-edit`,
  `totp-setup-edit`, `new-password` need `id` and a live grant on it (`no-grant` or
  `grant-expired`; the check never uses up a single-use grant, since nothing is read from
  the store); `create-password`, `create-notes`, `create-totp-setup` take no `id` (one is
  `invalid`, `field:"id"`). The window never sends it for the Apple ID password, the Apple
  2FA code or the old 1.x passphrase.
- `text`: 1 to 16384 characters after NFC, no NUL (else `invalid`, `field:"text"`).
- At most 10 per rolling minute per uid, then `rate-limited` with `retry_after`; this shares
  nothing with the dialog limits.
- The ticket carries `field:"text"`, the `id` (or none) and the text, `sensitive` true; as
  with `copy` it first withdraws the uid's previous offer, and a lock revokes it. The outcome
  arrives as the `clip` event with `"field":"text"`. The daemon never stores, logs or MACs
  the text.

### 6.6 set, create, delete, totp-preview

```json
{"op":"set","rid":10,"id":"<id>","fields":{"notes":"...","sites":["a.example.com"]}}
{"op":"set","rid":10,"id":"<id>","fields":{},"generate":{}}
{"op":"create","rid":11,"fields":{"domain":"example.com","username":"me","title":"Example"},"generate":{}}
{"op":"delete","rid":12,"id":"<id>"}
{"op":"totp-preview","rid":13,"setup":"otpauth://totp/...?secret=..."}
```

- `set` needs a grant on `id`. `fields` may hold any of `password` (string), `notes`
  (string), `sites` (array of strings), `nickname` (string), `totp`
  (`{"setup":"<key or otpauth link>"}` or `{"remove":true}`), `tags` (array of at most 16
  strings, each a tag with or without its `#`; `[]` removes the line). `notes` is the **body**:
  the daemon keeps the entry's current tag line under it, so editing the body never drops
  tags. Both `notes` and `tags` are spliced into the notes **as iCloud holds them at that
  moment** (fetched for the edit), never into a copy the window sent: a body edit replaces
  everything before the tag line, a tag edit replaces only that line and keeps every byte
  before it. Tags on notes whose stored bytes are not UTF-8 are refused before anything is
  written: `{"error":"invalid","field":"notes","detail":"not-utf8"}`. `set` on a passkey-only
  row or a Recently Deleted copy is `invalid` with `field:"id"`. `generate:{}` sets the password
  to a daemon-generated one in Apple's shape (`generate` and `fields.password` together are
  `invalid`); the generated value is never in the reply, only `reveal` shows it.
  Reply: `{"rid":10,"id":"<id>","synced":true}` (`synced:false` when only a local nickname
  changed). The old password moves into history. A `nickname` goes to iCloud like the other
  fields when the entry has a details record there (so every device shows it); otherwise,
  or with no iCloud session at all, it is kept on this computer only and `synced` is false.
- `create` needs `.manage` and tier 1. `fields` from `domain`, `username`, `password`,
  `title`, `notes`, `sites`, `totp`, `tags` (written as the notes' last line); a password is
  required unless `generate:{}`.
  Reply: `{"rid":11,"id":"<new id>"}`.
- `delete` needs `.manage` and tier 1. Reply: `{"rid":12,"deleted":true}`.
- `totp-preview` needs tier 1, no grant, reads nothing from the store: parses the setup text
  and replies `{"rid":13,"code":"123456","seconds":17,"issuer":"...","account":"..."}` or
  `invalid`.
- All three Apple-touching ops can fail with `not-signed-in`, `needs-login`,
  `anisette-unavailable`, `network`, `apple` (with a sanitized `detail`), `busy-sync`.
- Validation failures are `{"error":"invalid","field":"<name>"}`.

### 6.7 signin, answer, signout

```json
{"op":"signin","rid":14,"mode":"login"}
{"op":"signin","rid":14,"mode":"relogin"}
```

- `login` needs `empty` (a store is created first) or an unlocked store with no session
  (`invalid` with `field:"mode"` when a session exists: use `relogin`); `relogin` needs
  tier 1 and a stored session. Both raise `.manage`.
- While it runs, the daemon sends the sign-in stream (section 9.2) with `"rid":14`. Questions
  are `ask` events; the UI answers each with:

```json
{"op":"answer","rid":15,"ask_id":3,"value":"123456"}
{"op":"answer","rid":15,"ask_id":3,"cancel":true}
```

  `answer` replies `{"rid":15,"ok":true}` immediately, or `invalid` for an unknown or
  already-answered `ask_id`. `cancel:true` (or `cancel{target:14}`, or EOF) aborts the
  sign-in.
- Final reply: `{"rid":14,"ok":true}` or `{"rid":14,"error":"cancelled"|"needs-login"|...}`.
  A successful sign-in leaves the uid unlocked and starts a sync.
- `signout` needs `.manage` and tier 1: forgets the iCloud session; entries stay; then lock
  trigger `signout`.

```json
{"op":"signout","rid":16}                  -> {"rid":16,"signed_out":true}
```

### 6.8 sync, settings

```json
{"op":"sync","rid":17}                     -> {"rid":17,"queued":true}
                                              {"rid":17,"skipped":"locked"|"running"|"signed-out"|"needs-login"}
{"op":"settings","rid":18,"get":true}      -> {"rid":18,"settings":{...}}
{"op":"settings","rid":18,"set":{"grant_s":60}}  -> {"rid":18,"settings":{...}}
```

`sync` never prompts. While the store's `needs_login` latch is set (Apple asked for a person),
neither a `sync` op nor the 2-hourly schedule contacts Apple or repeats the `needs-login`
event; `sync` replies `skipped:"needs-login"` and only a `signin` clears the latch.
`settings` needs no dialog (the window is already the authenticated
app); `set` validates every key first and applies all or none. A lower `grant_s` applies to
the next grant; `idle_lock_s` restarts the idle clock.

### 6.9 Migration and cleanup

```json
{"op":"migrate-begin","rid":19}            -> {"rid":19,"ticket":"<43 chars>","ttl":10}
{"op":"purge-old-copy","rid":20}           -> {"rid":20,"ticket":"<43 chars>","ttl":10}
{"op":"reset","rid":21}                    -> {"rid":21,"state":"empty"}
{"op":"migrate-abandon","rid":24}          -> {"rid":24,"migration_pending":false}
{"op":"tpm-move","rid":25}                 -> {"rid":25,"sealed_with":"host+tpm2"}
{"op":"clip-history-check","rid":22,"items":["...","..."]}  -> {"rid":22,"matches":[0,4]}
{"op":"autofill-enable","rid":23,"enabled":true} -> {"rid":23,"autofill":{"enabled":true,"hosts":0}}
```

- `migrate-begin`: needs state `empty`, a store an earlier `migrate-begin` created that
  never committed (the daemon records `migration_pending` in state.json; that store holds
  keys and nothing else, and is started over: deleted when it keeps nothing, else renamed
  aside), or any store that holds nothing - no entry or history box, no iCloud session, no
  aliases or nicknames, read without a key - which is started over the same way (an import
  abandoned by mistake, or a store reset and never signed in, so a 1.x vault that is there
  can always still be moved).
  Otherwise `not-locked`. When a new store would certainly be refused (a TPM and a
  `tpm2-pcr-public-key.pem`), `seal-refused` with `reason:"pcr-policy"` comes before any
  dialog. Raises `.manage`, creates and seals new keys, opens tier 1 on this connection, and issues
  a `migrate`/`import` ticket. The
  UI runs `pear-exec migrate` with it (section 10.2). When the import commits, the UI gets
  `{"event":"migrated","counts":{...}}` and then the first `synced`.
- `purge-old-copy`: needs an `old_copy` record (`not-found` without one, before any dialog).
  Raises `.manage` and issues a
  `migrate`/`purge` ticket; the importer deletes exactly the recorded files whose sha256
  still matches and reports `purge-result`. The record is cleared afterwards.
- `tpm-move`: "Move your keys onto the security chip". Needs tier 1 and `tpm_move` (else
  `invalid` with `field:"tpm"`, or `seal-refused` with `reason:"pcr-policy"`). Raises
  `.manage`, then rotates to new keys sealed with host+tpm2 (security.md section 2): every
  entry and history box is opened once inside the daemon and re-sealed to the new public
  key. That is the only time boxes are opened outside a per-entry grant, which is why it
  runs only on this click. `seal-unavailable` if it did not verify; nothing changed then.
- `migrate-abandon`: no dialog. Drops a recorded `migration_pending` (and withdraws a
  running importer), so the store is an ordinary one and `signin` works again. The window
  sends it when it finds no importable 1.x vault left, or when you choose "Start fresh
  instead" over an unfinished move. It reveals nothing and changes no key; with nothing
  pending it is a no-op. Reply `{migration_pending:false}`.
- `reset`: allowed in `tpm-cleared`, `damaged`, while an import that never committed is
  recorded (`migration_pending`), and on a store that holds nothing (as for
  `migrate-begin`); else `not-locked`. `seal-refused`/`pcr-policy` before any dialog as for
  `migrate-begin`. Raises `.manage`;
  the old directory is renamed aside. After `tpm-cleared` or `damaged` it is always kept; a
  store that opens normally and keeps nothing (only key wrappers and settings: no entry or
  history box, iCloud session, aliases or nicknames) is deleted instead. The reply
  `state:"empty"` means "no entries and no iCloud session": the fresh store already has new
  sealed keys and tier 1 stays open on this connection, so the sign-in the UI then offers
  needs only its own
  `.manage` dialog. No `locked` event is sent; a later `hello` reports `locked`.
- `autofill-enable`: turning browser autofill on raises `.manage` (once; it is then remembered
  in state.json); turning it off never asks and closes every autofill connection of the uid.
  Until it is on, an autofill `hello` is `forbidden`.
- `clip-history-check`: needs tier 1. Raises `.manage`. At most 1000 items of at most 1024
  characters each, and the whole request must still fit one 64 KiB line, which binds first:
  the window sends only single-line history items without spaces of 4 to 256 characters,
  newest first, up to about 56 KB. Compares pwmac only (no entry key); `matches` are indexes into `items`.
  Values are never logged.

### 6.10 features, diag-items

```json
{"op":"features","rid":28,"get":true}      -> {"rid":28,"features":{"passkeys":false,"apple_deleted":false}}
{"op":"features","rid":28,"set":{"passkeys":true}}  -> {"rid":28,"features":{...}}
{"op":"diag-items","rid":29}
  -> {"rid":29,"available":true,"items":[{"class":"keys","agrp":"com.apple.webkit.webauthn",
      "count":22,"keys":["agrp","class","klbl","labl","v_Data"],"inner_keys":[]}]}
```

- `features`: the categories that wait for a check on a real keychain, `passkeys` and
  `apple_deleted`, both `false` until turned on. `get` never asks. A `set` that changes a
  flag raises `.manage`; the window alone can never change one. Remembered in state.json.
  Other keys or non-boolean values are `invalid`. While a flag is off its rows are left out
  of every list (section 3.1). After a change the window gets the list again as `synced`.
- `diag-items`: needs tier 1, raises `.manage`. What the last full sync since this unlock
  decrypted, as counts per (`class`, `agrp`) pair with the set of attribute names (`keys`)
  and, for password-manager metadata records, the names inside the blob (`inner_keys`).
  **Never a value**: names that are not plain identifiers show as `?`. `available:false`
  with no items before the first sync after an unlock; a lock forgets it. It exists to
  confirm the passkey and Recently Deleted names on the owner's keychain once, before those
  categories are turned on.

## 7. clip ops (role `clip`)

```json
{"op":"redeem","rid":1}
  -> {"rid":1,"value":"...","sensitive":true,"timeout":30}
{"op":"clip-result","rid":2,"outcome":"pasted"}
  -> {"rid":2,"ok":true}
```

- `redeem` works once per connection; a second one is `bad-ticket`. `sensitive` is true for
  `password`, `code`, `notes` and a `copy-text` selection. `timeout` is the uid's `clip_timeout_s`.
- `outcome`: `pasted` (the single counted paste), `expired` (timeout; cleared only if still
  the selection), `replaced` (someone else set the selection), `withdrawn` (the daemon sent
  `withdraw`), `failed` (no data-control protocol, compositor gone). The daemon relays it as
  `{"event":"clip","id":"<id>","field":"password","outcome":"pasted"}` to the UI.
- On `{"event":"withdraw"}` or EOF from the daemon the clip process destroys its source
  (clearing the clipboard only if its offer is still the selection), zeroes the value and
  exits.

## 8. migrate ops (role `migrate`)

Purpose `import`:

```json
{"op":"import-file","rid":1,"name":"vault.enc","seq":0,"b64":"...","eof":false}
  -> {"rid":1,"ok":true}
{"op":"import-file","rid":2,"name":"vault.enc","seq":1,"b64":"...","eof":true}
  -> {"rid":2,"ok":true,"size":123456,"sha256":"<hex>"}
{"op":"import-key","rid":3,"key_b64":"<32 bytes base64>"}
{"op":"import-key","rid":3,"passphrase":"..."}
  -> {"rid":3,"ok":true}  |  {"rid":3,"error":"wrong-passphrase"}
{"op":"import-commit","rid":4}
  -> {"rid":4,"counts":{"credentials":554,"history":31,"nicknames":12,"aliases":7,"session_keys":14},
      "digest":"<hex>"}
  |  {"rid":4,"error":"mismatch"}  |  {"rid":4,"error":"incomplete"}
```

- `name` must be one of `session.enc`, `vault.enc`, `history.enc`, `nicknames.enc`,
  `aliases.enc`, `kdf.json`, `check.enc`, `device.json`; `vault.enc` is required, and
  `kdf.json` with `check.enc` for a passphrase vault (a vault 1.x keyed by the login keyring
  has neither). Each file is sent in chunks of at most **32 KiB raw** with `seq`
  counting from 0; at most **4 MiB** per file. A repeated name after `eof`, a gap in `seq` or
  an oversize file is `invalid` and discards that file.
- `import-key` is checked against `check.enc` when it has arrived, else against `vault.enc`
  itself (a keyring-keyed vault; one of the two must have arrived, else `incomplete`).
  `passphrase` needs `check.enc` and runs Argon2id with the `kdf.json` parameters inside the
  daemon.
  A wrong key or passphrase changes nothing and may be retried.
- `import-commit` converts in `u<uid>.tmp`, verifies, and renames into place on a match. On
  `mismatch` nothing is kept and v1 stays authoritative. On success the daemon records
  `old_copy` with the sha256 of each imported file and the backup directory the importer
  reports via the `backup_dir` field: `{"op":"import-commit","rid":4,"backup_dir":"<abs path>"}`.

Purpose `purge`:

```json
{"op":"purge-result","rid":1,"removed":["vault.enc"],"kept":["session.enc"]}
  -> {"rid":1,"ok":true}
```

The `files` and `dir` from the purge hello are the only files the importer may unlink, and only
if their sha256 still matches.

## 9. Events

### 9.1 To the UI

```json
{"event":"locked","reason":"screen-locked"}
{"event":"synced","entries":[<Meta>...],"synced_at":1791450000.0,
 "counts":{"added":0,"changed":2,"deleted":0,"unchanged":552},
 "features":{"passkeys":false,"apple_deleted":false}}
{"event":"sync-failed","reason":"anisette-unavailable"|"network"|"needs-login"|"apple","detail":"..."}
{"event":"needs-login"}
{"event":"grant-expired","id":"<id>"}
{"event":"clip","id":"<id>","field":"password","outcome":"pasted"}
{"event":"clip","id":null,"field":"text","outcome":"expired"}
{"event":"autofill","id":"<id>","origin":"github.com","outcome":"filled"|"dismissed"|"denied"|"failed"}
{"event":"autofill-hosts","count":1}
{"event":"migrated","counts":{...}}
{"event":"focus"}
```

`focus` asks the window to raise itself (`hyprctl dispatch focuswindow`). `autofill-hosts` is
sent whenever an autofill host connects or goes, so the window can show that one is connected.
`synced` carries the `features` its list was made with (section 6.10), so the window's
category rows always match the rows it was sent.

### 9.2 Sign-in stream (to the UI, carrying the signin rid)

```json
{"event":"stage","rid":14,"stage":"verify","info":{"via":"device"}}
{"event":"out","rid":14,"kind":"step"|"out"|"warn"|"err","text":"..."}
{"event":"ask","rid":14,"ask_id":3,"need":"text"|"secret"|"confirm"|"choice",
 "kind":"code","prompt":"6-digit code: ","default":null,"detail":null,
 "options":["MacBook Pro"],"details":["Last used ..."]}
```

`options` and `details` appear only for `need:"choice"`; the answer `value` is then the index
as a string. For `confirm` the value is `"yes"` or `"no"`. These mirror the 1.x jsonui
frontend, so a stage Apple adds later reaches the window without a UI change.

### 9.3 To clip and migrate

`{"event":"withdraw"}`: stop now (lock, new copy, UI gone). The daemon closes the connection
right after.

### 9.4 To autofill

`{"event":"state","state":"locked"|"unlocked"|"unavailable"}` whenever the uid's tier 1 opens or
closes, so an extension can update its button. Carries nothing else.

## 10. UI to child (stdin/stdout of processes the UI spawns)

These pipes never leave the pair of processes: both ends are non-dumpable `pear-client`
processes of the same user.

### 10.1 `pear-exec clip`

- stdin: exactly one line, the ticket, then EOF.
- stdout: nothing the UI depends on (diagnostics only, never a value). The outcome reaches the
  UI through the daemon's `clip` event.
- exit 0 after reporting an outcome, non-zero if it could not connect or redeem.

### 10.2 `pear-exec migrate`

- stdin, line 1: the ticket. Line 2 (purpose `import` only): options
  `{"move_manifests":true|false}`. Later lines, only when asked:
  `{"passphrase":"..."}`, `{"check_keyring":true}` or `{"cancel":true}`.
- stdout: one JSON object per line:

```json
{"stage":"reading"|"peek"|"keyring"|"converting"|"cleanup"|"purging"}
{"need":"passphrase","retry":false}
{"need":"keyring-locked","retry":false}
{"done":true,"counts":{...},"digest":"<hex>","backup_dir":"<abs path>","kept_manifests":["..."]}
{"done":true,"removed":["..."],"kept":["..."]}
{"error":"wrong-passphrase"|"mismatch"|"unsafe-file"|"no-v1"|"no-key"|"daemon","detail":"..."}
```

- A passphrase vault (`kdf.json` and `check.enc`): the importer first PEEKs the 1.3.2 agent
  (never GET), then tries the 1.x key items in the login keyring (below). Only if both fail
  does it print `{"need":"passphrase"}`; the window shows its one field and writes the answer
  to stdin; the importer sends it as `import-key{passphrase}`. On `wrong-passphrase` it prints
  `{"need":"passphrase","retry":true}`.
- A keyring vault (`vault.enc` alone, 1.x's default): there is no passphrase. The importer
  reads the Secret Service items `{application: icp, type: master-key | lockbox-key}` from the
  session bus, from unlocked items only (`SearchItems`, `OpenSession("plain")`, `GetSecrets`;
  never `Unlock`, never a prompt, and a service that is not running is not started), and sends
  each as `import-key{key_b64}`; the daemon checks it against `vault.enc`. If only locked
  items exist it prints `{"need":"keyring-locked"}`, and the window says the login keyring
  is locked and to unlock it the way you usually do. Pear never asks the keyring to unlock
  (no `Service.Unlock`, no `Prompt`): its password dialog would be a second password prompt,
  and the one-time old passphrase is the only one besides polkit. On "Check again" the
  window writes `{"check_keyring":true}` and the importer reads the unlocked items again.
  Still locked: `{"need":"keyring-locked","retry":true}`. No key anywhere: the `no-key`
  error line, and nothing changed.
- `{"cancel":true}` (or EOF on stdin while asked) ends the importer with exit status 4 and no
  further output; nothing was changed. In purge mode a recorded file that is already gone is
  listed under `removed`.

## 11. Autofill (role `autofill`)

The autofill role is `pear-exec autofill`, started by a browser through the native-messaging
host `io.github.dragosol.pearpasswords` (wrapper `/usr/local/lib/pear-passwords/libexec/pear-autofill-host`).
It never gets a tier-1 or tier-2 grant and never uses the window's grants.

**Off until turned on in the window.** The `hello` is `forbidden` until `autofill-enable`, and
both ops answer `forbidden` once it is turned off again. Any program running as the user can
start `pear-exec autofill`, so once autofill is on, any such program can ask for fills: each
fill is still its own dialog, which says a browser extension is asking, and the window shows
when an autofill host is connected.

**A locked Pear reveals nothing.** `autofill-query` and `autofill-fill` work only while the
uid's tier 1 is unlocked in the Pear window, or the store is open for that very connection.
Otherwise they say nothing about any site. The store is opened for one autofill connection
only by `autofill-names`: with tier 1 closed, its approved `.autofill-names` dialog unlocks the
store for that connection (no tier 1, no grant, no sync). It locks again `AUTOFILL_OPEN_S`
(120 s) after that connection's last request, when the connection closes, or on any lock
trigger; if the window has tier 1 open by then, only the connection's access ends.

### 11.1 Origin

`origin` is the page origin as the browser reports it (the extension takes it from the tabs
API or `sender.url`, never from page content): exactly `https://<host>` or
`https://<host>:<port>`, ASCII host (punycode for IDNs), at least two dot-separated
`[a-z0-9-]` labels, no IP literal, no userinfo, path, query, fragment or trailing dot. Any
other scheme is `insecure-origin`; anything else malformed is `bad-origin`. One leading `www.`
is stripped; the port is ignored.

### 11.2 Matching

An entry matches host `h` when `h` equals its `domain` or one of its `sites`, or one is a
subdomain of the other at a dot boundary and the shorter one is not a public suffix (at least
two labels and not in the daemon's frozen list of multi-label public suffixes). Rank 0 is an
exact host match, rank 1 a related one. Name-only matches and inferred `aliases` never match.

### 11.3 Ops

```json
{"op":"autofill-query","rid":1,"origin":"https://github.com"}
  -> {"rid":1,"state":"locked"}
  -> {"rid":1,"state":"unavailable"}
  -> {"rid":1,"state":"unlocked","host":"github.com",
      "accounts":[{"id":"<id>","match":"exact"}]}
  -> {"rid":1,"state":"unlocked","host":"github.com",        (after an approved fill)
      "accounts":[{"id":"<id>","username":"me","label":"GitHub — me","match":"exact"}]}

{"op":"autofill-names","rid":3,"origin":"https://github.com"}
  -> {"rid":3,"state":"unlocked","host":"github.com",
      "accounts":[{"id":"<id>","username":"me","label":"GitHub — me","match":"exact"}]}
  |  {"rid":3,"state":"locked"}  |  {"rid":3,"error":"dismissed"|"denied"|...}

{"op":"autofill-fill","rid":2,"origin":"https://github.com","id":"<id>"}
  -> {"rid":2,"id":"<id>","username":"me","password":"...","code":"123456"}   (code: if it has one)
  |  {"rid":2,"error":"locked"|"no-match"|"dismissed"|"denied"|"no-agent"|"busy"|
                      "rate-limited"|"prompt-pending"|"cancelled"|"bad-origin"|"insecure-origin"}
```

- `id` in every autofill reply and request is a **handle**, never an entry id: `h-` and 32 hex
  characters of HMAC-SHA256(entry id) under a random key the daemon makes at each unlock and
  drops at every lock. Entry ids are an unkeyed hash of (domain, username), so a program given
  them could confirm a guessed username offline; a handle says nothing without the key, and a
  handle from before a lock is `no-match`. A real entry id sent to `autofill-fill` is
  `no-match` too. Handles are the same on every autofill connection during one unlock, so
  `sendNativeMessage` (a connection per message) works.

- `autofill-query` never prompts. Locked, without a UI connection, or for a uid the daemon
  has not seen since it started: only `{"state":"locked"}` (the autofill `hello` says the
  same); empty or a seal state: only `{"state":"unavailable"}`. Unlocked: up to
  20 accounts ranked by match, then newest change, then label. `username` and `label` are
  included only once a fill on this connection has been approved since the uid last
  unlocked, or for a host whose names `autofill-names` released to this connection since
  then; before that a query gives handles and match kinds only. Never a secret.
- `autofill-names` is `autofill-query` with that host's accounts named. Unavailable: the
  query's answer and no dialog. Locked: the dialog below also unlocks the store for this
  connection (above). Already named: the query's answer and no
  dialog. Otherwise it raises `.autofill-names` with `origin` (the host), in the `autofill`
  bucket; once approved, and the uid is still unlocked and the connection still open, that
  host's names go to this connection until the uid locks. No password and no other host's
  names are released.
- `autofill-fill` raises `.autofill` every time with `account` and `origin` (the host), in the
  `autofill` rate-limit bucket (one outstanding, 3 refused per minute per uid). An unknown
  handle and a non-matching one both give `no-match`. After approval the daemon re-checks that the
  uid is still unlocked and the entry still matches, opens the entry and replies with
  username and password, and the entry's current one-time code when it has one (the same
  approval covers a site's code step). It also sends the UI an `autofill` event.
- The browser, and the extension, then hold that one password. The origin is only as
  trustworthy as the browser that reported it.

## 12. Error codes

| code | meaning |
|---|---|
| `bad-request` | malformed JSON, wrong types, or a missing field |
| `too-large` | request line over 64 KiB; the connection is closed |
| `hello-required` | first line was not hello, or no hello within 5 s; closed |
| `proto` | unsupported `proto` in hello; closed |
| `unknown-op` | op name not in this protocol |
| `forbidden` | op not allowed for this connection's role |
| `too-many` | 16 requests pending, or 4 autofill connections already open |
| `already-running` | a second `ui` hello for this uid; the existing window is focused |
| `bad-ticket` | ticket missing, expired, used, of another role or uid, or wrong parent |
| `peer` | peer verification failed (sent only if the socket is still writable); closed |
| `internal` | a daemon bug; logged, never carries detail |
| `locked` | needs tier 1 and this uid is locked |
| `not-locked` | `migrate-begin` or `reset` in a state that does not allow it |
| `no-grant` | needs a grant on this id and there is none |
| `grant-expired` | the grant on this id ran out |
| `not-found` | no live entry with this id |
| `no-match` | autofill: unknown id, or the entry does not match the origin |
| `not-signed-in` | needs an iCloud session and there is none |
| `migration-pending` | `signin` login while a 1.x import was started and never committed |
| `needs-login` | Apple wants an interactive sign-in |
| `empty` | no store for this uid |
| `tpm-missing` | see section 4.1 |
| `tpm-cleared` | see section 4.1 |
| `damaged` | see section 4.1 |
| `seal-unavailable` | `systemd-creds` (or the G1 seal service) could not run at all; transient, never a seal state; try again |
| `seal-refused` | sealing ran but bound the keys to something Pear refuses, so nothing was kept: `reason` is `pcr-policy` (a `tpm2-pcr-public-key.pem` exists, so systemd binds new keys to a signed PCR policy) or `key-type` (a credential key type not on the allowlist confirmed on a real TPM). Not transient and not a seal state |
| `dismissed` | the user closed the dialog |
| `denied` | polkit refused (wrong password, failed fingerprint, policy) |
| `no-agent` | no polkit agent; not counted against the rate limit |
| `busy` | the agent is showing another dialog; not counted |
| `rate-limited` | 3 dismissed or denied dialogs of this action in the last minute in this bucket; has `retry_after` |
| `prompt-pending` | this bucket already has a dialog open |
| `cancelled` | cancelled by `cancel`, a superseding `grant`, or EOF |
| `busy-sync` | a sync, sign-in or edit for this uid is already running |
| `anisette-unavailable` | the anisette server on 127.0.0.1:6969 did not answer |
| `network` | iCloud could not be reached |
| `apple` | iCloud refused; a sanitized `detail` explains |
| `invalid` | a field failed validation; `field` names it |
| `wrong-passphrase` | the v1 key or passphrase does not open check.enc |
| `mismatch` | the converted store did not verify; nothing was kept |
| `incomplete` | `import-key` or `import-commit` before the files it needs |
| `bad-origin` | autofill origin malformed |
| `insecure-origin` | autofill origin is not https |

Errors never carry a secret, a file path under `/var/lib/pear-passwords`, or a Python
traceback.

## 13. Op table

| op | role | dialog | needs | reply |
|---|---|---|---|---|
| `hello` | all | – | first line | section 2.2 |
| `unlock` | ui | `.unlock` | store present | `{entries, synced_at, needs_login, tpm_move, features}` or `{locked, reason}` |
| `lock` | ui | – | – | `{locked:true}` |
| `release` | ui | – | – | `{released:true}` |
| `cancel` | ui | – | – | `{cancelled}` |
| `grant` | ui | – | tier 1 | `{id, expires, grant_s, single_use, fields}` |
| `reveal` | ui | – | grant | `{id, field, value, hide_after:20}` |
| `totp` | ui | – | grant | `{id, code, valid_until}` |
| `history` | ui | – | grant | `{id, items:[{date, value, source}]}` |
| `copy` | ui | – | tier 1; grant for password/code/notes | `{ticket, ttl:10}` |
| `set` | ui | – | grant | `{id, synced}` |
| `create` | ui | `.manage` | tier 1 | `{id}` |
| `delete` | ui | `.manage` | tier 1 | `{deleted:true}` |
| `totp-preview` | ui | – | tier 1 | `{code, seconds, issuer, account}` |
| `signin` | ui | `.manage` | section 6.7 | stream, then `{ok:true}` |
| `answer` | ui | – | a pending ask | `{ok:true}` |
| `signout` | ui | `.manage` | tier 1 | `{signed_out:true}` |
| `sync` | ui | – | – | `{queued:true}` or `{skipped}` |
| `settings` | ui | – | – | `{settings}` |
| `migrate-begin` | ui | `.manage` | state empty, migration_pending, or a store holding nothing | `{ticket, ttl:10}` |
| `migrate-abandon` | ui | – | – | `{migration_pending:false}` |
| `reset` | ui | `.manage` | tpm-cleared, damaged, migration_pending or a store holding nothing | `{state:"empty"}` |
| `purge-old-copy` | ui | `.manage` | an old_copy record | `{ticket, ttl:10}` |
| `clip-history-check` | ui | `.manage` | tier 1 | `{matches}` |
| `autofill-enable` | ui | `.manage` | – | `{autofill:{enabled, hosts}}` |
| `tpm-move` | ui | `.manage` | tier 1, `tpm_move` | `{sealed_with:"host+tpm2"}` |
| `copy-text` | ui | – | tier 1; grant for notes-edit, totp-setup-edit, new-password | `{ticket, ttl:10}` |
| `features` | ui | `.manage` | – (a change only) | `{features}` |
| `diag-items` | ui | `.manage` | tier 1 | `{available, items}` |
| `redeem` | clip | – | ticket at hello | `{value, sensitive, timeout}` |
| `clip-result` | clip | – | after redeem | `{ok:true}` |
| `import-file` | migrate | – | purpose import | `{ok, size?, sha256?}` |
| `import-key` | migrate | – | purpose import | `{ok:true}` |
| `import-commit` | migrate | – | files + key | `{counts, digest}` |
| `purge-result` | migrate | – | purpose purge | `{ok:true}` |
| `autofill-query` | autofill | – | – | `{state, host?, accounts?}` |
| `autofill-names` | autofill | `.autofill-names` | tier 1 (a site not yet named) | `{state, host?, accounts?}` |
| `autofill-fill` | autofill | `.autofill` | tier 1 | `{id, username, password, code?}` |
