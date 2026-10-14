# Pear Passwords 2: security design

This is the reviewer's document: what the parts are, who holds which key, what each check is,
what Pear defends against and what it does not, and which test proves each claim. Every claim
below ends with the tests that check it (`Tests:`); `backend/tests/test_docs_claims.py` fails if
a claim has none or names a test that does not exist. The wire protocol is in
[protocol.md](protocol.md), and the browser-facing autofill messages in
[autofill-protocol.md](autofill-protocol.md).

Owner decisions that override the original design: a per-account grant lasts **120 s**, a
clipboard offer **30 s**; the 1.x vault is imported **once**; browser autofill is a generic,
**opt-in** native-messaging host with **no bundled extension**; there is **no sync lease**, so
a locked computer does not sync.

## 1. Components

```
 you (uid 1000)                               |  pear-passwords (system user)
                                              |
 launcher ──> pear-exec ui ──> quickshell     |
              (root:pear-client 2755)  │      |
                                       │ one JSON-lines socket per process
              pear-exec clip ──> pear-clip ───┼──> /run/pear-passwords/client.sock
              pear-exec migrate ──> importer ─┤     (pear-passwords:pear-client 0660)
 browser ──> pear-autofill-host               |        │
              └─> pear-exec autofill ─────────┘        v
                                              |   pear-passwordsd ──> polkitd (system bus)
                                              |        │   CheckAuthorization(pidfd subject)
                                              |        ├──> systemd-creds (host key / TPM2)
                                              |        ├──> /var/lib/pear-passwords/u<uid>/
                                              |        └──> iCloud, anisette 127.0.0.1:6969
```

- **pear-passwordsd** runs as `pear-passwords`, socket-activated, with no capabilities,
  `ProtectSystem=strict`, `ProtectHome=yes`, private /tmp, devices and IPC, a native-only
  `@system-service` syscall filter without `@privileged`, `LimitCORE=0` and a CI exposure
  target of 2.5 or lower in `systemd-analyze security`. Tests: `test_unit_hardening.py`.
- **pear-exec** is the only way to get effective group `pear-client`, which is the only group
  that can open the socket. The group has no members, and the installer and the daemon refuse
  to run if it ever has. Tests: `test_pear_exec_env.py`, `test_daemon_peer.py`,
  `test_install_root_receipts.py::InstallRootTests`.
- **pear-exec** takes exactly one argument (`ui`, `clip`, `migrate` or `autofill`), refuses
  root, builds the environment from scratch (no `LD_*`, `PYTHON*`, `QT_PLUGIN_PATH`, `QML*`
  import paths; XDG homes pointed at an empty root-owned directory; `QML_DISABLE_DISK_CACHE=1`;
  a system-only fontconfig; for the window, a session-bus address nothing can listen on),
  checks that `WAYLAND_DISPLAY` is the user's oldest Hyprland, and
  executes a fixed root-owned argv only if every path and parent is root-owned and not group-
  or other-writable. The set-gid exec makes the child non-dumpable whatever `ptrace_scope` is.
  Tests: `test_pear_exec_env.py`.
- **The window** has no `IpcHandler`, renders every `Text` as plain text, logs no values, binds
  neither the primary selection nor a text-input protocol (`QT_WAYLAND_DISABLED_INTERFACES`
  from pear-exec, so there is no input method for CJK text either), keeps every field that
  holds a secret (notes, setup keys, typed and new passwords, the 1.x passphrase, the Apple
  password, the verification code) off the regular clipboard (Ctrl+C and the context menu's
  Copy go through pear-clip, one paste or 30 s; Ctrl+X does nothing; the Apple password, the
  2FA code and the 1.x passphrase copy nothing at all), and starts only a fixed list of
  programs. One of them is the QR scanner (app/qr_scan.py, root-owned): only when you press
  Scan QR code, it runs slurp for the area you drag, grim for just that area into an anonymous
  memory file (never a file on disk) and zbarimg on it, and hands back only what the code
  holds, into the setup-key field. Tests: `test_qr_scan.py`,
  `test_qml_process_allowlist.py`. **It is not on the accessibility bus.** Qt starts its AT-SPI bridge from the
  session bus, and any program of yours can switch `org.a11y.Status IsEnabled` on there (no
  privilege needed, even after the window has started); every field and label of the window,
  revealed passwords included, could then be read over AT-SPI and its buttons pressed through
  the Action interface (shown on Qt 6.11.2 in round 2 of the audit). pear-exec therefore gives
  the window a session-bus address in the root-owned empty directory, so the bridge never
  starts; the clip and migrate processes the window starts get the real bus back from their
  own pear-exec. As a second layer every secret field and every item that shows a revealed
  password, code or history value carries `Accessible.ignored: true`. The cost: screen readers
  cannot read Pear's window. Unsaved secret edits are discarded when the 120 s grant expires;
  editor fields are cleared, and a full lock clears creation and sign-in fields too. The
  Omarchy components it
  instantiates (Commons `Style`, `Color`, `Util`; Ui `Button`, `TextField`) add exactly
  `hyprctl -j getoption decoration:rounding|general:gaps_out` and `fc-match -f %{family[0]}
  monospace` (through PATH=/usr/bin, with egid pear-client) and read
  `~/.local/state/omarchy/current/theme/{colors,shell}.toml`, `~/.config/omarchy/shell.toml`,
  and (watch only) `~/.config/fontconfig/fonts.conf` and
  `~/.local/state/omarchy/toggles/hypr/window-no-gaps.lua`: a same-uid program can change the
  window's colours and sizes, not its contents. Both lists are pinned by tests, so an Omarchy
  update that adds to them fails. Quickshell's runtime directory lets the same user kill the
  window (`qs kill`); its log holds no account data. Tests: `test_qml_no_ipc.py`,
  `test_qml_text_plain.py`, `test_qml_no_console_log.py`, `test_qml_process_allowlist.py`,
  `test_qml_grant_flow.py`, `test_qml_secret_copy.py`, `test_qml_no_atspi.py`,
  `test_pear_exec_env.py`.
- **pear-clip** speaks the Wayland data-control protocol itself and holds the value in memory.
  It identifies each reader by the pipe it hands over, looking for it among your processes
  whose `/proc/<pid>/fd` it can read. Served: any such same-uid reader, and the compositor's
  X11 bridge, i.e. the compositor itself (the peer pear-exec verified) when it holds the
  pipe's read end, matched by inode and by an `O_RDONLY`/`O_RDWR` access mode in
  `/proc/<pid>/fdinfo`. Hyprland's XWM reads the value there for an X11 app; which X11 app
  asked is not visible, so the bridge is one reader, and it is served exactly once: no
  re-read inside the grace window, because a second read could be a different X11 client.
  The compositor holding only the write end is not a reader, and a compositor whose fds
  cannot be read is refused - that includes any compositor with file capabilities (Arch's
  sway has `cap_sys_nice`, so its `/proc` fd entries are closed to us and X11 pastes are
  refused there; checked in the gate VM). Hyprland as Omarchy runs it has none. Omarchy's history watcher gets nothing; the first served reader is the one counted
  paste (as soon as one byte of the value reaches its pipe, so a reader that stalls part-way
  has used it up; a write that takes no byte is not a paste), and the offer is withdrawn
  after that paste or 30 s. Refused, without counting: watchers, a reader nobody can
  identify (a pipe with no reader left, a compositor whose fds cannot be read), and any
  non-dumpable process, whose fds it cannot list. Pear's own window is one (set-gid,
  non-dumpable), and Qt reads the clipboard text the moment the selection changes to decide
  whether Paste is possible; before this rule that read used up the one paste. The cost: **a
  copied secret cannot be pasted into a non-dumpable program, Pear's own window included**,
  and an unidentifiable reader gets nothing. It never uses `wl-copy` (which stages its input
  in `/tmp`). Tests: `test_clip_policy.py` (including real non-dumpable readers and the
  XWayland bridge), `test_repo_guards.py::ClipboardGuardTests`.

## 2. Key hierarchy

Per user, in `/var/lib/pear-passwords/u<uid>/` (0700 `pear-passwords`; your uid cannot list it):

| File | What it is |
|---|---|
| `keys/list.cred` | `RK_list`, 32 random bytes, sealed by `systemd-creds --user` under uid `pear-passwords`. In uid scope the request goes through systemd's credentials service, which takes no PCR, public-key or (on systemd 261) key-type choice, so it always uses `auto`: host key, plus TPM2 when one is usable, no PCRs. Pear reads the key type back from the credential header and records that. It is an **allowlist** of the ids a real encryption produced on the gate VM (uid-scoped host `55b9ed1d…`, uid-scoped host+TPM2 `ef4ac136…` on systemd 261.2 and `2a1f877a…` on 262; the seal service: host `5a1c6a86…`, host+TPM2 `93a89409…` / `14142588…`); every other type is refused (`seal-refused`): a public-key-bound one by name (`pcr-policy`), anything else as `key-type`. With a TPM and a `tpm2-pcr-public-key.pem` nothing is sealed (that would bind the keys to a signed PCR policy): an existing host-sealed store stays host-sealed, and a new store cannot be created there |
| `keys/secret.cred` | `SK_secret`, the X25519 private key that opens entries, sealed the same way |
| `keys/secret.pub` | `PK_secret` plus a MAC under the metadata key, so it cannot be swapped |
| `meta.v2`, `aliases.v2`, `nicknames.v2`, `session.v2` | XChaCha20-Poly1305 under subkeys of `RK_list` (HKDF-SHA256), with the file kind, uid and name in the associated data |
| `entries/<id>.box`, `history/<id>/<n>.box` | `crypto_box_seal` to `PK_secret`, padded, with the id inside |

- A file that fails to decrypt is reported as `damaged` and **never deleted**; files cannot be
  swapped between names or users. Tests: `test_store_v2.py`.
- Sync and edits write with the public key only and detect changes with
  `HMAC(K_pwmac, password)`, so sync never unseals `SK_secret`. Tests:
  `test_pwmac_sync_diff.py`.
- In memory: nothing while locked; `RK_list`, its subkeys and the metadata after the first
  dialog; one entry's fields for at most the grant (120 s) after the second. Tests:
  `test_grants.py`, `test_logind_lock.py`.
- **The tag line is tier-1 list metadata.** Whatever is on a note's final `Tags:` line is list
  metadata, not a secret: it is visible to anyone who passes the first dialog, like titles and
  usernames. Do not put secrets on that line. The daemon reads it from the plaintext a sync,
  an edit, a new entry or the 1.x import already holds, without unsealing `SK_secret`, and
  keeps it in `meta.v2`; the box keeps the whole notes, and `reveal`/`copy` of notes give only
  the body. A tag edit is an edit: it needs that entry's grant and splices the one line into
  the notes as iCloud holds them at that moment. Tests: `test_tagline.py`,
  `test_store_v2.py::TagMetaTests`, `test_pwmac_sync_diff.py::TagSyncTests`,
  `test_push_details.py`, `test_daemon_handlers.py::NotesBodyTests`.
- **Passkey key material is never stored.** A passkey is a class `keys` item in the WebAuthn
  access group; its `v_Data` is its private key. The daemon deletes `v_Data` from every
  decrypted `keys` item before anything else reads it, so no credential, box, `meta.v2` record
  or reply ever holds it; what is kept is the site, the account name and the fact that a
  passkey exists. Pear never creates, uses or deletes a passkey. Items in Apple's Recently
  Deleted (access groups ending in `-recently-deleted`) are kept apart from the live entry
  under their own id: never merged into it, never listed as live, never offered to autofill,
  never edited. Both categories stay hidden until a `.manage`-gated flag turns them on, after
  `diag-items` (counts and attribute names only, never a value) confirmed the names on a
  real keychain. Tests: `test_host.py::PasskeyTests`, `test_host.py::RecentlyDeletedTests`,
  `test_host.py::ShapeTests`, `test_push_details.py`,
  `test_daemon_handlers.py::FeatureFlagTests`, `test_daemon_handlers.py::DiagItemsTests`.
- A lock never waits. It runs on the daemon's one event loop, and a store call can sit in
  `systemd-creds` for up to a minute on a slow TPM, so a lock that finds a store call running
  marks the uid locked and asks the store to wipe: the store method in progress wipes the keys
  the moment it returns (still holding the store's mutex), and every store method after it is
  refused, also later steps of the same daemon call, so a sync that was locked part-way never
  writes again. A sync also checks between its network steps and stops talking to Apple.
  PrepareForSleep holds the suspend back for one second at the most.
  **Sleep while a store call runs** (residual): if a store call is still running when that
  second is up (an unseal on a hung TPM, a sync), the machine sleeps with that call's keys
  in RAM, and they are wiped when that one store method returns after resume. This holds
  for a call that makes a new store too (`create`/`reset`, in `migrate-begin`, `reset` and
  the first sign-in): the wipe stays pending until it returns, the new store's keys are then
  wiped, and the op ends `cancelled` without opening tier 1, so the window is locked after
  resume. Tests: `test_lock_never_waits.py`, `test_lock_during_create.py`.
- Moving to host+TPM2 is never automatic. With a usable TPM and host-sealed keys the unlock
  reply says `tpm_move`, and Settings offers **Move your keys onto the security chip**, which
  raises its own `.manage` dialog (op `tpm-move`). It is a key rotation, not a re-wrap: a new
  `RK_list` and `SK/PK`, every file re-encrypted and every box re-sealed in `u<uid>.rotate`,
  read back through a real unseal and compared, then swapped in with one
  `renameat2(RENAME_EXCHANGE)`; the old tree is deleted at once and a leftover is removed by
  the next unlock. **It is a one-time, daemon-internal step, and the only time SK_secret opens
  boxes outside a per-entry grant**: each entry and history box is opened inside the daemon,
  re-sealed to the new public key at once and dropped before the next one (Python cannot zero
  it), then opened once more under the new key to verify. No plaintext leaves the daemon, and
  the window receives nothing but `sealed_with`. That is why it waits for the user's click and
  its own dialog instead of riding on polkit #1. No host-only copy of a key that opens current data survives, so
  a pre-PTT backup opens only the vault as it was then. A missing TPM is told apart from a
  cleared one. A cleared TPM is recognised by its storage key fingerprint where systemd-tpm2-setup
  writes one (measured, UKI boots); on other boots (Limine or GRUB without a UKI) a working
  TPM that refuses the keys is reported as `tpm-cleared` too, with "most likely" wording. A
  failure of the mechanism itself (the credentials service unreachable, a busy or locked-out
  TPM) is transient and never becomes a seal state: a non-zero exit counts as a refusal only
  when a throwaway value still round-trips. Tests: `test_daemon_handlers.py::TpmMoveTests`,
  `test_seal_reseal.py::TpmMoveStateTests`, `test_seal_reseal.py`,
  `test_seal_reseal.py::CommandLineTests::test_key_type_is_an_allowlist`,
  `test_seal_service.py`.

## 3. Peer verification

On every accept the daemon reads `SO_PEERCRED` (gid must be `pear-client`, uid at least
1000), takes `SO_PEERPIDFD` for the life of the connection, checks `/proc/<pid>/status`
(real gid = the user's, effective = `pear-client`, real = effective uid), records the start
time and confirms the pid is still that process by polling the pidfd (it turns readable when
the process exits; a signal 0 would be EPERM for another uid's process). One `ui` connection per uid;
`clip` and `migrate` need a single-use ticket issued on that uid's UI connection within 10 s,
and must be children of that UI process. Tests: `test_daemon_peer.py`, `test_tickets.py`,
`test_protocol_limits.py`.

## 4. Prompts

Four polkit actions, each `auth_self` for active sessions and `no` for any and inactive, with
no `_keep` and the owner annotation `unix-user:pear-passwords` that lets the non-root daemon
check other users' subjects. The subject is the caller's pidfd. Tests: `test_policy_file.py`,
`test_policy_readme_sync.py`, `test_repo_guards.py::PolicyGuardTests`,
`test_daemon_polkit.py`.

- Only the ops in protocol.md section 5 raise a dialog, with user interaction allowed only
  while handling one of them; one outstanding dialog per bucket (`ui` and `autofill`), and at
  most three refused (dismissed or denied) dialogs per minute per bucket and action; approvals
  are not counted. A polkitd refusal of the call itself is `internal`, never "no agent". Tests: `test_daemon_polkit.py`, `test_protocol_contract.py`.
- **copy-text: no dialog, text already in the window; fixed sources; 16 KiB; 10/min; one
  offer at a time.** Ctrl+C and Copy in the window's secret fields send the selection to the
  daemon, which puts it on the clipboard through pear-clip (one paste or the clipboard
  timeout, kept out of history) like any copy. It raises no dialog, because the text is
  already in the window and a prompt would protect nothing; the guard exists so the honest
  window never puts a secret on the persistent clipboard. Only six named fields may send it;
  the three edit fields need a live grant on that entry, which the check never uses up. At
  most 16384 characters, no NUL, 10 per minute per user, and a new one withdraws the last
  offer. The text lives only in the ticket (the same Python-string residue as `copy`).
  Tests: `test_daemon_handlers.py::CopyTextTests`, `test_protocol_contract.py`.
- **Only polkitd's own reply is an answer.** Every D-Bus call the daemon and the importer make
  goes through `icp/dbus_safe.py`: a message answers a call only if it is a method return or an
  error, carries the call's reply serial, and was sent by the unique name that owned the
  destination when the call went out (asked of the bus driver under the same rule; the bus
  stamps the sender and no client can set it). The polkit check then reads only a method return
  as a result. jeepney 0.9 matches replies on the serial alone, so in 2.0.0 a program running
  as you could send the daemon directed signals with guessed serials and an "authorized" body
  and be taken for polkitd (HANCORE-linux, omacom/omarchy-plugin-marketplace#10755); fixed in
  2.0.1. Signals from logind count only from logind's own unique name, and they can only lock
  Pear. Tests: `test_dbus_forged_reply.py` (that attack on a real dbus-daemon: jeepney's router
  takes the forgery, Pear's returns polkitd's denial), `test_dbus_safe.py`,
  `test_daemon_polkit.py::AuthorityTests::test_only_a_method_return_can_authorize`.
- **A malformed message cannot stop the daemon listening.** Any local user can send the
  daemon's bus connections a signal, and dbus-broker passes on header fields it does not know.
  jeepney 0.9 raises on those, and in 2.0.0 that ended the thread that receives: until the
  daemon restarted, sleep, a session ending and logind's `Lock` (from lockers that send it)
  no longer wiped keys. Closing the window still did, and so did the idle lock if it was on.
  Since 2.0.1 a message that cannot be parsed is dropped (its file descriptors
  closed) and the connection carries on, and a message that breaks its handler is logged and
  skipped. Tests: `test_dbus_malformed_message.py` (on a real dbus-broker: jeepney's router
  dies, Pear's drops the message and still receives and calls),
  `test_dbus_safe.py::TolerantParserTests`, `test_dbus_safe.py::RouterReceiverTests`.
- The scheduler and the Apple pipeline never import or name the polkit module, and no
  `AllowUserInteraction` appears in them. Tests: `test_scheduler_no_prompt.py`,
  `test_repo_guards.py::BackgroundNeverPromptsTests`.
- Nothing else prompts: no zenity, `systemd-ask-password`, getpass or passphrase prompt
  anywhere in the backend or the window, and no terminal step. The one exception is the
  one-time in-window field for the old 1.x passphrase, and only for a passphrase vault whose
  key neither the 1.3.2 agent nor the login keyring still has. A 1.x vault keyed by the login
  keyring is moved with its key read from the unlocked keyring over D-Bus and checked against
  `vault.enc`; if the keyring is locked, Pear never asks it to unlock (its password dialog
  would be a second password prompt): the window says so, you unlock it the way you usually
  do, and **Check again** only reads again. Tests:
  `test_no_secret_prompts.py`, `test_apple_ctx.py`,
  `test_migrate_client.py::KeyringVaultTests`, `test_migrate_client.py::SecretServiceKeyringTests`.

## 5. Autofill

- Off until the user turns it on in the window (`autofill-enable`, one `.manage` dialog): until
  then the daemon refuses the autofill `hello`, and turning it off disconnects every host.
  The browser manifest is not the opt-in, because `pear-exec autofill` runs for any program
  of the user. No installer writes a manifest; `unregister` removes only a manifest whose hash
  its receipt recorded. Tests: `test_daemon_handlers.py::AutofillOptInTests`,
  `test_autofill_register.py`, `test_repo_guards.py::InstallerWritesNoManifestTests`.
- While autofill is on, any same-uid program can connect as an autofill host. A query gives it
  handles only, no usernames or labels, until a fill on that connection is approved or, for one
  site, an `autofill-names` request's `.autofill-names` dialog ("A browser extension asks to see
  which accounts you have saved for *site*") is approved; those names last until Pear locks and
  never include a password. Every fill is its own `.autofill` dialog, which says a browser extension is asking, and the window shows
  when a host is connected. Residual: a program that gets the user to approve one fill dialog
  receives that password. A handle is HMAC-SHA256 of the entry id under a key that exists only
  while the uid is unlocked, never the entry id itself (an unkeyed hash of domain and username,
  which would let a program confirm a guessed username offline). Tests:
  `test_autofill_handlers.py::HandleTests`, `test_autofill_handlers.py`,
  `test_autofill_handlers.py::QueryTests::test_names_for_one_site_cost_one_dialog_and_no_secret`,
  `test_autofill_host_framing.py`.
- While the uid is locked, `autofill-query` answers only `locked` (or `unavailable`), and
  `autofill-fill` answers `locked`: nothing reveals which sites have accounts. Every fill
  raises `.autofill` with the account and the origin's host, and is re-checked after approval.
  An unknown id and a non-matching id give the same `no-match`. Tests:
  `test_autofill_handlers.py`.
- **The browser can unlock Pear for itself, briefly, behind one dialog.** With the window
  closed or locked, an approved `.autofill-names` dialog unlocks the store for that one autofill
  connection: no tier 1, no grant, no sync, and other connections still get `locked`. It locks
  again 120 s after that connection's last request, when it disconnects, or on any lock
  trigger (sleep, logind, the window's own lock). Every fill still raises `.autofill`. Residual:
  a program that gets that dialog approved learns one site's account names and can then ask
  for fill dialogs without the window open. Tests: `test_autofill_browser_unlock.py`.
- Origins must be `https` with an ASCII host; matching is exact host or a dot-boundary
  sub/parent domain that is not a public suffix. Tests: `test_autofill_origin.py`,
  `test_autofill_host_framing.py`.

## 6. Installer

- The root step runs from a root-owned copy of the stage checked against the published hash of
  `SHA256SUMS`; it refuses symlinks and unlisted files, installs wheels offline with
  `--require-hashes`, and compiles `pear-exec` from source. Tests:
  `test_sha256sums_current.py`, `test_install_root_receipts.py::InstallRootTests`.
- A path is overwritten or removed only if its bytes are the staged file, the receipt's record,
  or a frozen released copy (the 1.x `org.icp.unlock.policy`). Foreign, edited and symlinked
  destinations, same-named units, drop-ins and policies, and a `pear-client` group with members
  stop the install before any write. Tests: `test_install_root_receipts.py::InstallRootTests`.
- Two kinds of path under the install prefix are not proven by hash, and both are names only
  the installer uses there, inside root-owned `/usr/local/lib/pear-passwords`:
  `venv.new/` (a venv being built) and `venv.old/` (the previous venv during a swap). Their
  contents are not checked; once every other path is proven ours (a receipt exists and
  everything else matches it) they are deleted and the venv is rebuilt from the hashed wheels.
  A `<dest>.pp-new` beside a destination (a copy an interrupted run did not finish) is
  checked: it must be owned by root and be a byte prefix of the file being installed there
  (for a link, a link to the same target), or the install stops; it is deleted before
  anything is written, and uninstall deletes the ones beside every path in its receipt, so
  the prefix is removed completely. Tests:
  `test_install_root_receipts.py::InstallRootTests::test_a_leftover_pp_new_is_checked_and_cleaned`,
  `test_install_root_receipts.py::InstallRootTests::test_a_pp_new_that_is_not_part_of_the_staged_file_is_in_the_way`,
  `test_install_root_receipts.py::UninstallRootTests::test_uninstall_removes_pp_new_leftovers_so_the_prefix_is_gone`,
  `test_install_root_receipts.py::InstallRootTests::test_a_venv_new_is_never_deleted_before_the_prefix_is_proven_ours`.
- Uninstall removes only receipt-matching files, keeps edited ones in the receipt, and keeps
  the vault and the service user unless `--purge <uid>` is confirmed by typing. Tests:
  `test_install_root_receipts.py::UninstallRootTests`.
- The user step removes 1.x files from your home only on an exact hash match. Tests:
  `test_install_user_files.py`.

## 7. Threat model

| Attacker | Outcome | Notes |
|---|---|---|
| A copy of `~/.config/icp` or all of `/home` | Holds | After the move nothing in `/home` decrypts anything; the renamed v1 backup is sealed by the old passphrase only. |
| A program running as you, any `ptrace_scope` | Mostly holds | No socket access except the autofill role while autofill is on, no state access, no unseal, no ptrace or `/proc` reads of Pear's processes, no injection. Residual: clipboard during an offer, screen capture of a revealed value, starting Pear to show a dialog, an autofill fill dialog approved by mistake (that one password), an autofill names dialog approved by mistake (one site's account names, and 2 minutes of fill dialogs it can raise), a rival polkit agent phishing the login password, denial of service, and control of the compositor (below). |
| Another local user | Holds | Per-uid state; the subject's uid must match; `auth_self`. |
| Remote login as you | Holds | `allow_any=no`, `allow_inactive=no`; pear-exec needs a local compositor. |
| Network | Holds | TLS verified, `trust_env=False`, no redirects, `icloud.com` endpoint check. |
| Disk image or backup of `/` with the host key, PTT off | Does not hold | Only LUKS protects it. |
| The same with PTT on | Holds | Blobs need this TPM. A pre-PTT copy still opens the data as it was then (the keys were rotated, so nothing written later); delete such snapshots. |
| Stolen laptop, off, suspended or hibernated | Holds | Keys wiped on PrepareForSleep (and on logind Lock and LockedHint where the locker sends them). |
| Stolen laptop, awake behind Omarchy's screen lock, Pear unlocked | Does not hold | Omarchy's lock emits neither Lock nor LockedHint and G6 is not built: the keys stay until Lock, window close, idle lock or sleep. |
| A program running as you, through the accessibility bus (AT-SPI) | Holds | The window has no session bus, so Qt's AT-SPI bridge never starts, whatever `org.a11y.Status` says; secret fields are also `Accessible.ignored`. Screen readers cannot use the window. |
| A program controlling the compositor (Hyprland plugin load or virtual keyboard/pointer, allowed by Hyprland's default `ecosystem:enforce_permissions = false`) | Does not hold | Sees what the window shows (the unlocked list, revealed values), reads what is typed into it (Apple password, 1.x passphrase, new passwords), can click Copy inside an approved grant and remove `no_screen_share`. Mitigation: `enforce_permissions = true` with `permission` rules denying `plugin` and `keyboard`, screen capture on ask. |
| Root, the kernel, `empower`, `/etc/polkit-1/rules.d` | Not defended | Same position as systemd-homed. |
| Old v1 ciphertext in snapshots | Residual | Crackable by guessing the old passphrase. |

Tests for the locking rows: `test_logind_lock.py`. Tests for the network row:
`test_authenticated_transports.py`, `test_webauth.py::TlsVerificationTests`.

## 8. Verification gates (VM, before release)

These are run in an Arch VM with swtpm and a nested Hyprland, never on the owner's laptop, and
their results are recorded here. Each has a decided fallback.

**TPM path re-gated on the current code (v2 at a1fbb64, 2026-10-08)**, in the same Arch VM
(KVM, OVMF UEFI, swtpm), installed with the real stage and root command as an upgrade over the
earlier gate install, with **no test patch** to the daemon (the peer fix is in the tree), and
driven through polkit with the session text agent:

| Step | Result |
|---|---|
| Key types, measured with real `systemd-creds` encryptions (systemd 262, and 261.2 by downgrading the VM) | uid scope: host `55b9ed1d…` (both), host+TPM2 `ef4ac136…` (261) and `2a1f877a…` (262). System scope: host `5a1c6a86…`, host+TPM2 `93a89409…` (261) / `14142588…` (262). With a `tpm2-pcr-public-key.pem`: uid scope `adbc4ca3…` (261) / `16e49294…` (262), and those blobs do not decrypt ("PCR signature required"). These are the allowlist in section 2. |
| No TPM: the 1.x import (passphrase path), two unlocks, grants, reveal, history, code | **Passes.** `keys.json` `sealed_with: host`, both blobs `55b9ed1d…`. |
| A TPM appears (fresh swtpm): unlock | **Passes.** The unlock reply says `tpm_move: true` and changes nothing (`sealed_with` stays `host`). |
| **Move your keys onto the security chip** (`tpm-move`, its own `.manage` dialog) | **Passes.** The rotation, including `renameat2(RENAME_EXCHANGE)`, ran inside the hardened unit (MDWE, the syscall filter) in 1.5 s; `sealed_with: host+tpm2`, both blobs `2a1f877a…`; no `u1000.rotate` left; the next unlock, a grant, the revealed password and its history are the same as before the move. |
| TPM removed | **Passes.** `unlock` gives `tpm-missing`. With the same TPM back, it opens again. |
| A different (cleared) TPM, no SRK PEM (non-UKI boot) | **Passes.** `unlock` gives `tpm-cleared`; Start over moved `u1000` aside to `u1000.broken-<time>` and made a new store sealed host+TPM2 (`2a1f877a…`). |
| A TPM and a `tpm2-pcr-public-key.pem`, new store (`migrate-begin`) | **Passes.** After the dialog: `seal-refused`, `reason: pcr-policy`; no key was written. That run also left an empty `u1000/` skeleton, which is fixed since (`test_seal_reseal.py::RefusedCreateTests`). Since round 2 the refusal comes before the dialog (`test_seal_reseal.py::CreateBlockedTests`). |
| The same PEM, an existing host-sealed store | **Passes.** The unlock reply says `tpm_move: false`; `tpm-move` answers `seal-refused` (`pcr-policy`) with no dialog; the store stays host-sealed and keeps opening. |

Not run on a real TPM chip (PTT on the owner's laptop): that is the XPS step after this.

**Earlier gate run, v2 at 380de03** (2026-10, on the build box): a podman Arch container with
systemd as PID 1 for the install path, G1 host key, G2, G3, G4, G5 at `ptrace_scope` 0, G7, G8
and `systemd-analyze`; an Arch cloud-image VM (KVM, OVMF UEFI, swtpm) for `ptrace_scope` 0, 1
and 2, the TPM re-seal (the automatic re-wrap of that code, since replaced by the rotation above),
`tpm-missing`, `tpm-cleared` and autofill. As shipped at 380de03 every
connection was refused (the peer liveness check used signal 0, which is EPERM for another
uid's process); the gates below ran with that one line patched in the test environment, and
the fix is now in the tree (`test_daemon_peer.py`). Real Hyprland could not run headless there
(no DRM render node), so G3 and G5 used a test build of `pear-exec` that accepts sway as the
compositor, and the real Omarchy polkit agent was replaced by pkttyagent's text agent
registered for the session. Not run: real Hyprland, the Omarchy agent (fingerprint first),
XWayland paste, the clipboard under load, G6, and a real browser extension.

| Gate | What | Result | Fallback | How the fallback is switched on |
|---|---|---|---|---|
| G1 | `systemd-creds --user` from uid `pear-passwords` inside the hardened unit | **Passes** with the host key: round trip, wrong `--name` refused, tampered blob refused. **TPM path: passes on the current code** (the round-1 table above): the move onto the TPM behind its own dialog, `tpm-missing`, `tpm-cleared` without an SRK PEM, and the PEM refusal. It needs UEFI: under legacy BIOS (SeaBIOS) `has-tpm2` reports `-firmware` and Pear stays host-sealed. (At 380de03, `tpm-cleared` failed and the re-seal was a re-wrap; both were replaced, and this row's earlier TPM result no longer applies.) The fallback also passed (bonus run, 380de03). | root's `pear-passwords-seal.socket` (Accept=yes) runs system-scope `systemd-creds` for the daemon, one request per connection, only for the daemon's uid and `pear.(list\|secret).u<uid>` names (`icp.vstore.seal_service`) | an active `Environment=PEAR_SEAL_BACKEND=seal-service` line in the shipped `pear-passwordsd.service`; `install-root.sh` then enables the seal socket (installed, never enabled, otherwise) |
| G2 | polkit accepts a pidfd `unix-process` subject; `$(account)` shows | **Passes** (with the liveness fix): the owner annotation is what lets uid `pear-passwords` check other users' subjects (`nobody` gets `NotAuthorized`); the dialog showed `Use the saved password for Work GitHub — dev@example.test`; grants are per entry; a seatless session and a process with no session are denied with no dialog. | `{pid, start-time, uid}`, fixed message | `Environment=PEAR_POLKIT_SUBJECT=pid-start-time` in the shipped unit |
| G3 | Quickshell starts with egid != rgid under AT_SECURE | **Passes** (sway build): Quickshell ran with `Gid: 1000 969 969 969`, passed the daemon's peer checks, unlocked through polkit and drew the list. Labels and background did not draw in the container either with or without set-gid (no theme there); to be checked visually on the XPS. | redesign the identity step | none: no release without one of the two |
| G4 | Quickshell with empty XDG homes and no disk cache; what it opens under `$HOME` | **Passes, with residue now documented** (section 1): QML only from `$P/app` and `/usr/share/omarchy`; under `$HOME`: `~/.drirc` (Mesa), Omarchy's theme and toggle files, and the `hyprctl`/`fc-match` children; Quickshell's runtime directory lets the same user `qs kill` the window; `qs ipc show` is empty and its log holds no account data. | allowlist the residue | docs only (and pinned by `test_qml_process_allowlist.py`) |
| G5 | pear-clip can identify a reader's pipe at `ptrace_scope` 1 and 2 | **Passes** at 0, 1 and 2: Omarchy's history watcher never got the password, the first paste got it and a second reader nothing, no paste expires at 30 s, an unrelated copy is `replaced` and survives, `x-kde-passwordManagerHint` offered. `mem`, `environ`, `fd`, `maps` of the UI and clip processes are EACCES and PTRACE_ATTACH EPERM at every scope. | a 250 ms window, documented as weaker | `READER_POLICY = "timing"` in `icp/client/clip.py` (root-owned; pear-exec passes no environment) |
| G6 | logind `Lock`, `LockedHint`, `PrepareForSleep` with Omarchy's lock | **Not run.** Omarchy's lock emits neither `Lock` nor `LockedHint` (checked in its source), so a screen lock does not lock Pear; README and section 7 say so. | forward Hyprland's lock event | **not built**: window close, the Lock button, idle lock and sleep lock either way |
| G7 | what `CheckAuthorization` returns with no agent | **Passes**: `[false, true, {"polkit.result":"auth_self"}]` in 1-2 ms with no `polkit.dismissed`, reported `no-agent`; a wrong password is `denied` after 2.3 s. A polkitd refusal of the call itself is now `internal`, not `no-agent`. | under 300 ms non-dismissed failure = no agent | this classification is what ships |
| G8 | `MemoryDenyWriteExecute=yes` with cffi, cryptography, srp; Argon2id at 256 MiB | **Passes**: PyNaCl, cryptography (P-384, X25519, AES-GCM, HKDF) and srp work under MDWE; Argon2id moderate took 0.17 s, 293 MiB maxrss. Old-style cffi `ffi.callback` would fail, and the code does not use it. | drop MDWE, documented | delete the `MemoryDenyWriteExecute=yes` line |

Also from that run: the install path, re-runs, upgrades and every refusal passed; uninstall
left `/run/pear-passwords/client.sock` behind and with it the identities (fixed: the sockets
`RemoveOnStop=yes`, uninstall removes stale runtime sockets and keeps itself while the
identities stay); idle exits logged an unlink error for systemd's socket (fixed:
`cleanup_socket=False`); an ABI mismatch restarted into the start limit (fixed:
`RestartPreventExitStatus=78`); the three-a-minute dialog limit blocked a third account
(fixed: only refusals count, per action). `systemd-analyze security`: 1.5 for
`pear-passwordsd.service`, 1.2 for `pear-passwords-seal@.service`; `systemd-analyze verify`
clean. Failed dialog passwords count toward `pam_faillock` like any other: three wrong ones
lock the account for ten minutes (Arch's default).

Tests for the switches: `test_seal_service.py`, `test_install_root_receipts.py::InstallRootTests::test_seal_service_runs_only_when_the_daemon_unit_selects_it`, `test_daemon_polkit.py`, `test_clip_policy.py::TimingFallbackTests`.

## 9. Rejected simplifications

Each of these was considered and rejected because it leaves a hole:

| Option | Why it fails |
|---|---|
| A user-level agent behind polkit (1.3.x) | Any process running as you skips the gate and talks to the agent or reads its files; the verdict is an exit code your own code reads. |
| `systemd-creds --user` alone | Any process of your uid decrypts it with no prompt (tested). |
| App-side system-scope `systemd-creds decrypt` | `auth_admin_keep`: one approval lasts about 5 minutes, per-account prompts stop working, the message cannot be branded, and the plaintext lands in a process running as you. |
| A daemon that serves any same-uid caller after polkit | An impostor can trigger a genuine-looking dialog and receive the result. The autofill role is the one accepted exception, off until turned on in the window, with a dialog that names a browser extension and no account names before an approved fill or an approved request to see one site's names. |
| `wl-copy` for secrets | wl-clipboard 2.3.0 stages its input in a `/tmp` file. |
| A timing grace window for clipboard readers | It hands the value to whoever reads first; reader identification replaces it. |
| A user sync timer or a sync lease | Background activity that could prompt, or hold Apple tokens while the window is closed. |
| A bundled browser extension | Not reviewable as part of the plugin; the generic host plus a documented protocol replaces it. |

## 10. Corrections to earlier claims

1.x documentation and comments said things that were wrong. For the record:

- "polkit-1 includes system-auth" (in the 1.x policy comment and README): it does not on Arch;
  `/etc/pam.d/polkit-1` has its own stack. Fingerprint works because Omarchy configures it.
- "`ALWAYS_CHECK` forces a prompt": it only affects root subjects. 2.0 relies on plain
  `auth_self` without `_keep`, which prompts every time. Tests: `test_policy_file.py`.
- "Same-uid code can read the agent's key through `/proc`": wrong at `ptrace_scope` 1 or more
  for a process that is not a descendant. The 1.x agent's real weakness was the socket, which
  any same-uid process could talk to.
- The 1.x `appapi` comment "can already read vault.key" was stale: 1.0.1 removed `vault.key`.
- The 1.x comment that `wl-copy -o` clears the clipboard after one paste was false: `-o` serves
  one paste and exits, and the timer it relied on cleared whatever was on the clipboard then.

## 11. Open items

- The anisette base images' `apt-get` packages are resolved at build time and not pinned
  ([anisette-provenance.md](anisette-provenance.md)).
- Gates G6 (screen lock) and the parts of G3/G5 that need real Hyprland and the Omarchy
  polkit agent have not run (section 8).
- Python cannot reliably zero memory; QML strings cannot be zeroed at all. A revealed value is
  overwritten after 20 s or on focus loss, not wiped.
