# Pear Passwords autofill host: native-messaging protocol

Status: protocol version 2, the first version of this host. This page is for people who want a
browser extension to fill logins from Pear Passwords. Pear Passwords ships **no extension**:
it provides a native-messaging host that any extension can talk to, once you have allowed that
extension yourself. Everything the host says to the daemon is in `docs/protocol.md` section 11;
this page covers what an extension sends and gets back.

The code is `backend/icp/client/autofill.py` (the host),
`backend/icp/daemon/autofill.py` (matching and the two daemon ops) and
`backend/icp/client/autofill_register.py` (the opt-in command). The tests are
`backend/tests/test_autofill_*.py`.

---

## 1. What you get, and what it costs

- Each fill raises its own Pear dialog (polkit action `io.github.dragosol.pearpasswords.autofill`,
  "A browser extension asks to fill the password for *account* on *site*"), answered with your
  fingerprint or login password. There is no "remember" and no session: two fills are two
  dialogs.
- Autofill is off until you turn it on in the Pear window (Settings, one Pear dialog). Until
  then the host is refused (`disabled`). Registering a browser is not enough, on purpose: the
  host program runs for any program of yours, not only for your browser. Once it is on, any
  program running as you can ask for a fill the way an extension does; it still gets nothing
  without your approval of that fill's dialog, but if you approve a dialog you did not trigger
  from your browser, that program gets that password. The Pear window shows when an autofill
  host is connected.
- The Pear window does not have to be open. While Pear is locked or closed, `query` and
  `fill` say only `locked` (or `unavailable` when it is not set up), without a dialog and
  without saying whether the site has accounts. `names` (4.3) is the one way in: its dialog
  unlocks Pear for your host process only, until 2 minutes after its last request, until it
  disconnects, or until any other lock.
- After an approved fill, **the browser and the extension hold that one password.** Whatever
  can read the extension's memory or the page's form can read it. The origin is only as
  trustworthy as the browser that reported it.
- Your picker can show which account is which before any fill: `names` (4.3) raises one Pear
  dialog, "A browser extension asks to see which accounts you have saved for *site*", and once
  approved that site's names and usernames are yours until Pear locks. Without it, or a fill,
  a query gives only opaque handles, so a program you did not approve learns nothing.
- One autofill dialog open at a time, and after 3 dismissed or denied ones in a minute no more
  for the rest of it (approvals are not counted). The window has its own separate allowance,
  so a page cannot use autofill to block it.

## 2. Turning it on (off by default)

Two steps. First, in the Pear window: Settings, "Browser autofill", **On** (one Pear dialog;
**Off** never asks and disconnects every host at once). Then nothing is installed into any
browser until you do it, as yourself, once per browser:

```sh
pear-passwords-autofill register --browser zen --extension-id '{5ad01040-3351-492c-9a42-1d56b881da78}'
pear-passwords-autofill status
pear-passwords-autofill unregister --browser zen
pear-passwords-autofill unregister --all
```

- Browsers: `firefox`, `zen`, `librewolf` (Firefox ids: `name@example.org` or `{GUID}`) and
  `chromium`, `chrome`, `brave`, `vivaldi`, `edge` (32-letter ids, `a` to `p`).
- `register` writes `io.github.dragosol.pearpasswords.json` into the browser's user manifest
  directory and allows exactly the extension id you name:
  - Firefox: `~/.mozilla/native-messaging-hosts/`, or `$XDG_CONFIG_HOME/mozilla/...` when
    `~/.mozilla` does not exist.
  - Zen: the Firefox directory, plus `~/.zen/native-messaging-hosts/` (and
    `$XDG_CONFIG_HOME/zen/...` if that is a separate directory).
  - LibreWolf: `~/.librewolf/native-messaging-hosts/`.
  - Chromium family: `$XDG_CONFIG_HOME/<browser>/NativeMessagingHosts/`.
  The browser must have been started once, so that its profile directory exists.
- Each written file's sha256 is recorded in `$XDG_STATE_HOME/pear-passwords/autofill-receipts`.
  `register` refuses to replace a file it did not write. `unregister` deletes a file only while
  its hash still matches; a file you edited is left in place and reported, and the command
  exits 1. The directories always come from the built-in browser table, never from the receipt.
- Registering again for the same browser replaces that browser's extension id. Firefox and Zen
  share one file in `~/.mozilla`; each keeps its own id in it.
- The manifest is the template `system/native-messaging/io.github.dragosol.pearpasswords.json.in`.
  `path` is the root-owned wrapper `/usr/local/lib/pear-passwords/libexec/pear-autofill-host`,
  which runs `pear-exec autofill` and drops whatever arguments the browser adds.

Restart the browser after registering.

## 3. Transport

Standard WebExtension native messaging (`runtime.connectNative` or `runtime.sendNativeMessage`
with host name `io.github.dragosol.pearpasswords`):

- Each message is a 32-bit length in native byte order followed by that many bytes of UTF-8
  JSON. The browser does the framing for you.
- Extension to host: at most **64 KiB** per message. A larger length prefix ends the session:
  the host answers `{"rid":null,"error":"too-large"}` and exits.
- Host to extension: at most 1 MiB per message, the browsers' own limit. A reply that would be
  larger becomes `{"rid":n,"error":"too-large"}`.
- Use `connectNative` and keep the port open while you need it. You then get `state` events
  (section 5) and a pending fill is cancelled when you disconnect. `sendNativeMessage` works
  too, at the cost of a new host process and daemon connection per message.
- The host keeps one daemon connection per process. The daemon allows 4 autofill connections
  per user; a fifth gets `too-many`.

## 4. Requests

Every request is a JSON object with `op` and `rid`. `rid` is an integer from 0 to 2^53-1,
chosen by you, and echoed in the reply. Replies can arrive out of order, because a fill waits
for a dialog while a query does not. At most 8 requests may be pending; the ninth gets
`too-many`. Unknown fields are ignored. They are never passed on: the host rebuilds each
request for the daemon from `origin` and `id` only.

### 4.1 status

```json
{"op":"status","rid":1}
-> {"rid":1,"state":"locked","version":"2.0.0"}
```

`state` is `locked`, `unlocked` or `unavailable` (section 5). Connects to the daemon if needed.

### 4.2 query

```json
{"op":"query","rid":2,"origin":"https://github.com"}
-> {"rid":2,"state":"locked"}
-> {"rid":2,"state":"unavailable"}
-> {"rid":2,"state":"unlocked","host":"github.com",
    "accounts":[{"id":"<opaque>","match":"exact"}]}
-> {"rid":2,"state":"unlocked","host":"github.com",          (after an approved fill)
    "accounts":[{"id":"<opaque>","username":"me@example.com","label":"GitHub — me@example.com",
                 "match":"exact"}]}
```

- Never raises a dialog and never returns a secret.
- `locked` and `unavailable` replies carry nothing else: no count, no hint.
- `accounts`: at most 20, exact matches first, then related ones (section 6), newest change
  first within each group. `id` is an opaque handle; pass it back unchanged to `fill`. It is
  valid until Pear next locks (then query again: an old handle is `no-match`), it is the same
  for every host process during one unlock, and it is not derived from the username in any
  way you could check. `username` and
  `label` (what the Pear dialog shows) are included only after a fill (or `names` for this site) through this host
  process was approved since Pear was last unlocked; before that, show "Account 1, 2, ..."
  with a way to ask `names` (4.3), and let the Pear dialog name the account.
- An empty list means no account for this site.

### 4.3 names

```json
{"op":"names","rid":4,"origin":"https://github.com"}
-> {"rid":4,"state":"unlocked","host":"github.com",
    "accounts":[{"id":"<opaque>","username":"me@example.com","label":"GitHub — me@example.com",
                 "match":"exact"}]}
-> {"rid":4,"state":"locked"}
-> {"rid":4,"error":"dismissed"}
```

- A `query` whose accounts carry `username` and `label` for this site. If the site is not
  named yet (no approved fill or `names` for it on this host process since Pear last
  unlocked), Pear first shows its `.autofill-names` dialog naming the site. Approved: the site
  stays named for every later `query` and `names` on this host process until Pear locks, with
  no further dialog. Other sites are not named by it.
- Never returns a secret. Unavailable: the `query` answer, and no dialog. Locked (the window
  closed or locked): the same one dialog also unlocks Pear for this host process, until 2
  minutes after its last request, until it disconnects, or until any other lock. Other host
  processes still get `locked`.
- Errors are the ones a fill's dialog can give (4.5), plus `bad-origin`/`insecure-origin`.
- Keep the host process alive between popups (a long-lived `connectNative` port) or the names
  are asked for again; `sendNativeMessage` starts a new host process each time.

### 4.4 fill

```json
{"op":"fill","rid":3,"origin":"https://github.com","id":"<opaque>"}
-> {"rid":3,"id":"<opaque>","username":"me@example.com","password":"...","code":"123456"}
-> {"rid":3,"error":"dismissed"}
```

Raises the Pear dialog. The reply arrives when the dialog is answered, which can take half a
minute (the fingerprint reader times out before the password field appears). After approval
the daemon checks again that Pear is still unlocked and that the account still matches the
origin; if either changed during the dialog, the fill fails. The username and password are
returned, and `code`, the account's current one-time code, when it has one: the same approval
covers a site's code step. Never notes or the code's seed.

### 4.5 Errors

`{"rid":n,"error":"<code>"}`, sometimes with `field` or `retry_after`:

| code | meaning | what an extension should do |
|---|---|---|
| `locked` | Pear is locked or its window is closed | ask `names` (4.3), which unlocks it for you |
| `no-match` | the id is unknown, or its sites do not match this origin (the same answer for both) | query again |
| `dismissed` | you closed the dialog | nothing |
| `denied` | authentication failed | nothing |
| `no-agent` | no polkit agent is running (the desktop shell may be restarting) | ask the user to try again |
| `busy` | the agent is showing another dialog | try again later |
| `prompt-pending` | an autofill dialog is already open | wait for it |
| `rate-limited` | 3 dismissed or denied dialogs in the last minute; `retry_after` is in seconds | wait |
| `cancelled` | the fill was cancelled (for example the daemon saw the port close) | nothing |
| `bad-origin` | the origin is malformed (section 6) | fix the extension |
| `insecure-origin` | the origin is not https | do not offer autofill on this page |
| `bad-request` | a missing or mistyped field; `field` names it (`rid` is null if the rid itself was bad) | fix the extension |
| `unknown-op` | `op` is not `status`, `query` or `fill` | fix the extension |
| `too-many` | 8 requests already pending, or the daemon's 4 autofill connections are in use | wait |
| `too-large` | a message over the size limit | fix the extension |
| `no-daemon` | the Pear service is not reachable (not installed, or stopped) | say so |
| `disabled` | autofill is switched off in the Pear window | say "Turn on autofill in Pear Passwords" |
| `internal` | a daemon bug | report it |

## 5. Events

```json
{"event":"state","state":"locked"|"unlocked"|"unavailable"}
```

Sent when the host first reaches the daemon, whenever the window locks or unlocks, and as
`unavailable` if the daemon connection is lost (pending requests then fail with `no-daemon`).
Use it to enable or disable your fill button. `unavailable` means Pear is not set up here, its
security chip is missing or was reset, its data is damaged, or the service is unreachable. The
host does not say which. No other event is ever sent.

## 6. Origins and matching

**Origin.** Send the page origin as the browser reports it, never as the page claims it. Take it
from the tabs API (`new URL(tab.url).origin`) or from `MessageSender.url` / `sender.origin` of
your own content script, not from `document.location` values passed through page script.
The daemon accepts exactly:

- `https://<host>` or `https://<host>:<port>`;
- an ASCII host (IDNs in punycode, as `URL.origin` gives them), at least two dot-separated
  labels of `a-z`, `0-9` and `-`, and a last label that is not all digits;
- no IP literal, userinfo, path, query, fragment, trailing dot or whitespace.

Upper case is folded. One leading `www.` is ignored. The port is ignored for matching. Any
other scheme is `insecure-origin`, so `http:` pages never get a password.

**Matching.** An account matches host *h* when *h* is its website or one of its extra websites
(`exact`), or when one is a subdomain of the other at a dot boundary (`related`), for example
`login.github.com` and `github.com`. Two more rules apply:

- The shorter of the two must be a registrable domain, not a public suffix. It needs at least
  two labels and must not be on Pear's built-in list of shared suffixes (`co.uk`, `com.au`,
  `github.io`, `herokuapp.com`, ...). There is no full public suffix list on the system, so
  siblings never match: `mail.example.com` does not fill an account saved for
  `accounts.example.com`, and `evil.github.io` never fills `github.io`.
- Only stored websites count. Titles, nicknames and the "also used on" sites Pear infers from
  Apple's metadata never match, and neither do Apple's own internal records.

## 7. Writing an extension

The rules an extension must follow to be a reasonable client:

1. **Fill only after a user action**: a click in your popup or page UI, or a keyboard shortcut.
   Never query or fill on page load or on focus. Every fill shows a system dialog, so filling
   without a click would put up dialogs the user did not ask for.
2. **Take the origin from the browser** (section 6), at the moment of the action.
3. **Fill only frames on that origin.** Before writing the password into a frame, check that the
   frame's own origin equals the origin you asked for. A cross-origin iframe must not receive it.
4. **Keep the password only as long as filling takes.** Do not store it, log it, or send it to a
   content script on another origin.
5. **Show `locked` / `unavailable` plainly.** The host will not tell you more, by design.

A minimal background-script sketch (Firefox, MV3):

```js
const port = browser.runtime.connectNative("io.github.dragosol.pearpasswords");
let rid = 0;
const waiting = new Map();
port.onMessage.addListener((m) => {
  if (m.event === "state") { /* update the toolbar button */ return; }
  const done = waiting.get(m.rid); waiting.delete(m.rid); if (done) done(m);
});
const ask = (msg) => new Promise((ok) => { const r = ++rid; waiting.set(r, ok);
                                           port.postMessage({ ...msg, rid: r }); });

// on a click or a shortcut, never on page load:
const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
const origin = new URL(tab.url).origin;
const q = await ask({ op: "query", origin });
if (q.state === "unlocked" && q.accounts.length) {
  const r = await ask({ op: "fill", origin, id: q.accounts[0].id });  // Pear dialog
  if (r.password) { /* inject into frames whose origin === origin, then drop r */ }
}
```

The owner's own extension, which follows these rules, lives in a separate repository and is
not part of Pear Passwords.

## 8. Security notes

- The host runs as `pear-exec autofill`, which gives it the `pear-client` group and makes it
  non-dumpable. It holds no key and no account list. It translates messages and nothing else.
- The extension is untrusted. The daemon trusts only the origin, and only as far as the browser
  is trusted. A compromised browser can claim any origin and so obtain the password for any
  account whose fill you approve. The dialog names both the account and the site; read it.
- A locked Pear reveals nothing to autofill: not the account list, not whether a site has
  accounts, and not which of the `unavailable` cases applies. Saying so needs no dialog. Only
  an approved `names` dialog unlocks it, for that one host process, briefly.
- Every fill is checked against the autofill process's own pidfd. It never uses a grant the
  window holds, and the window's grants never apply to it.
- The window gets an `autofill` event (filled, dismissed, denied or failed) for each answered
  dialog, so it can show what the browser was given.
