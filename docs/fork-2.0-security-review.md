# Fork security review: upstream 2.0.3

Reviewed on 2026-10-14 for `kabucey/omarchy-pear-passwords` only.

Upstream baseline: `a7399ae3f495ad94d95c3e656e9f1985c740e46c` (2.0.3).
Previous fork main: `b9bc6ff`; combined pending hardening: `eb46058`.

## Decision

Merge 2.0.3 and retain the missing protections described below. The separate service-user
architecture is a stronger local security boundary than the 1.x user-owned key agent and
CLI authentication gate. This conclusion concerns the protections in the seven old PRs;
it is not a claim that every new feature or deployment has received an independent audit.

## Disposition of the old PRs

| Fork PR | Protection | 2.0.3 comparison and final disposition |
| --- | --- | --- |
| [#1](https://github.com/kabucey/omarchy-pear-passwords/pull/1) | Verified TLS; no environment proxy/CA overrides or authenticated redirects; Apple endpoint validation; scoped cookies | The original commit `6d8cc8a` is in upstream history. Endpoint and HTTP helpers, GSA, escrow and CloudKit protections remain; web-auth differs only in explanatory comments from the hardened branch. Retain upstream implementation. |
| [#2](https://github.com/kabucey/omarchy-pear-passwords/pull/2) | Trusted executable paths, permissions and environment for pkexec | Original commit `b6cf934` is in upstream history, but 2.0 removes the pkexec fallback entirely. `native/pear-exec.c` checks root-owned paths and parents, uses fixed role targets and builds an allowlisted environment. The daemon checks peer identity and authenticates through polkitd. Replaced by the stronger service boundary. |
| [#3](https://github.com/kabucey/omarchy-pear-passwords/pull/3) | No usable persisted passphrase-derived key; recoverable migration; runtime invalidation | The old agent, held-key and lockbox modules are removed. Keys are sealed under the separate service identity, with optional TPM binding; the user's home no longer holds the current decrypting key. The v1 importer builds and verifies a separate store before committing and keeps the v1 source until success. This replaces the old passphrase-mode implementation. |
| [#4](https://github.com/kabucey/omarchy-pear-passwords/pull/4) | Fail closed on expiry; clear secret UI/input state; avoid clearing someone else's clipboard | Backend grants are now per account, checked against the clock and wiped on expiry; clipboard offers are withdrawn on paste, expiry, replacement or lock. Upstream retains unsaved secret drafts after grant expiry and defaults idle locking to off. This fork removes secret-draft retention, clears editor fields on expiry and creation/sign-in fields on full lock, and enables five-minute idle locking by default. |
| [#5](https://github.com/kabucey/omarchy-pear-passwords/pull/5) | Multi-device escrow stage argument collision | Original standalone commit `9207510` is in upstream history. The stage discriminator uses `stage_name`, so device metadata named `name` cannot collide. Retain upstream implementation. |
| [#6](https://github.com/kabucey/omarchy-pear-passwords/pull/6) | Authenticate every app create/unlock/elevation path; fail closed | The old appapi/fallback gate is removed. The daemon gates list unlock, per-account grants and management operations, validates authorization outcomes and rechecks state after approval. 2.0.1 also rejects forged D-Bus replies and malformed messages. Retain the new implementation. |
| [#7](https://github.com/kabucey/omarchy-pear-passwords/pull/7) | Complete pagination/decryption before vault updates; atomic encrypted writes; corruption errors | V2 files use authenticated encryption bound to file kind/name/uid and atomic fsync/rename writes; damaged encrypted metadata raises an error. Upstream still silently skips missing/undecryptable items and accepts incomplete pagination, which can incorrectly tombstone an existing entry when some other entries decrypt. This fork restores strict pagination/zone completeness and aborts on missing item keys/data or authentication/plist failures before `apply_sync`. |

## Retained fork changes

- All requested CloudKit pages must finish with status 3. Missing or repeated continuation
  tokens, unexpected status, parser failures and zone transport errors abort the snapshot.
  An optional zone is allowed to be absent only when CloudKit identifies it as absent before
  any page loads; Passwords and Manatee must succeed.
- Foreign TLK shares are ignored; relevant shares must decrypt. Every fetched item must have
  its key/data and authenticate and parse successfully. A partial plaintext snapshot never
  reaches the daemon's vault apply step or receives a successful sync timestamp.
- Idle locking defaults to 300 seconds; saved user settings still take precedence. This is
  an idle timer, whereas the old fork's list lock was five minutes after authentication.
  V2's per-account approvals provide narrower secret access during that interval.
- Approval expiry discards unsaved secret edits. Tags are list metadata and may still be
  kept. A full lock also clears creation, verification-code and sign-in input fields.
- Installation instructions use the kabucey fork. Installer hashes are regenerated for the
  actual fork code; upstream's published installer hash does not describe this tree.

## Evidence and limitations

The new sync tests exercise real AES-SIV encryption/decryption through the daemon sync
boundary with offline network fixtures. A complete snapshot succeeds; incomplete decryption
and pagination tests failed against the unmodified upstream implementation. The secret-edit
expiry test executes the real QML JavaScript cleanup functions and failed against upstream's
draft retention. The idle-lock test drives the real daemon registry/server and scheduler on
a temporary socket and proved the default did not lock before the change.

Final validation: **1,378 tests passed** in 89.91 seconds, including offscreen Qt runtime,
D-Bus spoofing/malformed-message, authentication, native launcher, migration, encrypted store,
installer and sync-integrity coverage. The suite initially selected Qt 5's
`/usr/bin/qmltestrunner`; the eight runtime failures reproduced on untouched upstream.
Selecting Qt 6 fixed them without changing or skipping tests.

Reproduce with the locked runtime dependencies and pytest installed in a temporary venv:

```sh
mkdir -p /tmp/pear-qt6-bin
ln -sf /usr/lib/qt6/bin/qmltestrunner /tmp/pear-qt6-bin/qmltestrunner
PATH=/tmp/pear-qt6-bin:$PATH PYTHONPATH=backend /tmp/pear-review-venv/bin/python \
  -m pytest backend/tests -q -p no:cacheprovider
sh tools/gen-sha256sums.sh --check
```

The test process needs permission to create temporary sockets and D-Bus test buses. The fork
changes pass `git diff a7399ae --check`. Whitespace inherited from upstream's anisette patch
context lines is unchanged.

Remaining upstream limitations relevant to deployment:

- Omarchy screen locking does not itself notify Pear (upstream security gate G6). Idle locking
  bounds unattended exposure but is not an immediate screen-lock hook. Close the window or
  press Lock for an immediate lock.
- Without TPM binding, a full disk/host-key backup can decrypt sealed keys. Home-directory
  isolation is stronger; it does not replace disk encryption.
- Python and QML do not guarantee erasure of immutable plaintext memory. Clearing references
  and UI fields removes accessible state, not every historical RAM copy.
- V2 provides atomic individual file writes, not a transaction spanning every file in a sync.
- Autofill is opt-in; any same-user program can request its dialogs while enabled. Approving
  a fill releases that account's password to the requesting host.
- No live Apple account, installed service, real TPM, browser extension, or real desktop
  migration was exercised during this repository merge. The installed app and vault were
  not modified.

## Preserved history

The old work is retained under `archive/pre-2-main-2026-10-14` and
`archive/pre-2-hardened-2026-10-14`. The second tag contains the stacked hardening changes;
the standalone escrow fix is already in upstream ancestry. Old fork PRs are closed as
superseded, rather than being merged into the removed 1.x architecture.

## Installer checksum

SHA-256 of this fork's `SHA256SUMS`:

```text
2b675fdb6876ab6bfc2f6dc2ed7c9747c2b27a33284ef786308b0108e634234a
```

Check against this document at the reviewed fork commit. Regenerate this value after any
subsequent change to installed files with `tools/gen-sha256sums.sh`.
