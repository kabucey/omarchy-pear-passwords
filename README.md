# Pear Passwords

Your passwords on iCloud, in a native Omarchy window.

![Pear Passwords](preview.png)

Sign in with your Apple Account, approve this computer once, and your passwords and
verification codes stay in sync.

![The window](docs/window.png) The window follows your Omarchy theme and is built from
Omarchy's own shell components.

> Pear Passwords is an independent project. It is not made, endorsed or supported by Apple.
> iCloud and Apple Account are Apple's trademarks, used here only to say
> what this works with.

## What it does

- **Your passwords on iCloud, synced.** It signs in as a Mac would, is approved as one of your devices once, then
  syncs every two hours and when you open it. Apple should not ask for a code again unless it
  signs you out.
- **Locked until you say so.** Names, sites and usernames stay hidden until you unlock with your
  fingerprint or password. That one scan then covers everything for two minutes, so a normal
  visit never asks twice.
- **Click to copy.** Username, password, website and verification code. Copied passwords clear
  themselves from the clipboard.
- **Add passwords.** **+ New** saves a login to iCloud, with a generated password if you want
  one, and optional notes and verification code.
- **Edit what Apple stores.** Extra websites, notes and verification codes. Set up a code by
  pasting the setup key or link, or scan the QR code straight off your screen, and see the
  live code before you save.
- **Password history.** Changes seen during sync are kept, alongside the history Apple stores.
- **Change a password, one at a time.** Writes back to iCloud, so your other devices get it.
  Each change is written and read back on its own; nothing rewrites your passwords in bulk, and
  an edit outside the unlocked window asks you to prove it's you first.
- **Strong, memorable passwords.** The generator uses the same six-six-six shape as Apple's.
- **Names that sync.** Rename an entry here and the name shows up on your other devices too.
- **Wi-Fi passwords.** Your saved networks, shown as networks rather than websites.
- **Search that understands what you want.** Type a name or site, or one of these to filter:

  | Search | Shows |
  | --- | --- |
  | `2fa`, `mfa`, `2fa codes`, `verification codes` | entries with a verification code |
  | `notes` | entries with notes |
  | `websites` | entries with a website |
  | `wifi` | Wi-Fi networks |

- **Keyboard first.** Arrows to move, Tab into the details, Enter to copy, Esc to go back.

## Install

```bash
omarchy plugin add https://github.com/dragosol/omarchy-pear-passwords.git --enable
cd ~/.config/omarchy/plugins/io.github.dragosol.pear-passwords
./install.sh
```

Then search **Pear Passwords** in the launcher. The window floats, centred, at the 960×640
it is designed for. It registers that with Hyprland each time it opens, so nothing is added
to your Hyprland config.

`install.sh` runs as your user and never uses sudo. It installs, all under your home directory:

| What | Where |
| --- | --- |
| The backend (Python, in its own virtualenv) | `~/.local/share/pear-passwords/venv` |
| The app window (Quickshell) | `~/.local/share/pear-passwords/app` |
| The launcher | `~/.local/share/applications/pear-passwords.desktop` |
| Sign-in helper + 2-hourly sync (systemd user units) | `~/.config/systemd/user/pear-passwords-*` |

Requires `python3`, `podman`, `quickshell` and `wl-clipboard`. Scanning QR codes also
uses `grim`, `slurp` and `zbar`. After
`omarchy plugin update`, run `./install.sh` again to pick up the new version.

### Opening it

Pear Passwords is a standalone app, not a panel in Omarchy's bar. Open it from the launcher
like any other app: search **Pear Passwords**. It runs as its own window on purpose, because
plugins inside the shell share one QML scene and can reach each other's objects, which is no
place for decrypted passwords.

A bar icon or panel version is possible. If enough people ask for one in the
[issues](https://github.com/dragosol/omarchy-pear-passwords/issues), I can build it.

### First sign-in

The first launch opens straight into sign-in:

1. **Apple Account and password.** Your password is saved encrypted on this computer so the app
   can stay signed in on its own.
2. **Verification code**, sent to your other Apple devices.
3. **Approve this computer.** Pick one of your devices and enter its **lock-screen passcode**
   (iPhone, iPad) or **login password** (Mac). This is how Apple lets a new device read your
   passwords without another device approving it.

> [!WARNING]
> Step 3 is the one step that can't be undone. Apple allows about 10 wrong passcode attempts per
> device. After the 10th, Apple permanently destroys that device's escrow record, and it can no
> longer be used to add new devices. Your passwords on devices that already trust you are not
> affected. The app shows this warning before you type, and **Not now** backs out without
> spending an attempt.

## Optional

### A dedicated unlock prompt

Unlocking always goes through Omarchy's polkit overlay, so your fingerprint works either way.
What this optional file changes is *what* that prompt is:

| | Without it | With it |
| --- | --- | --- |
| The prompt says | "run `/usr/bin/true` as root" (via `pkexec`) | "Unlock Pear Passwords" |
| Runs as root | a command that does nothing | nothing at all |
| Who can pass it | an administrator | you, as yourself |

It is one file. Copy the command as a whole, so nothing from the plugin folder is ever run as root:

```bash
sudo tee /usr/share/polkit-1/actions/org.icp.unlock.policy >/dev/null <<'POLICY'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC
 "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/software/polkit/policyconfig-1.dtd">
<policyconfig>
  <vendor>Pear Passwords</vendor>

  <!-- Re-authentication for passwords that are already unlocked. auth_self prompts via the desktop
       polkit agent for whichever factors PAM offers - here the user's own password, or a
       fingerprint, because polkit-1 includes system-auth and that carries pam_fprintd.

       This gates nothing privileged: it is checked with pkcheck, which runs no command. The
       derived vault key still comes from the passphrase; this only decides whether an existing
       agent lease may be used without retyping it. -->
  <action id="org.icp.unlock">
    <description>Unlock Pear Passwords</description>
    <message>Authenticate to view your saved passwords</message>
    <defaults>
      <allow_any>auth_self</allow_any>
      <allow_inactive>auth_self</allow_inactive>
      <allow_active>auth_self</allow_active>
    </defaults>
  </action>
</policyconfig>
POLICY
```

The action only asks you to authenticate as yourself (`auth_self`) and grants nothing
privileged. Without it, unlocking still works: it falls back to `pkexec`, which asks for an
administrator and runs a no-op command as root to prove it.

## Security

- **Its own process.** The window is not loaded into `omarchy-shell`. Plugins inside the shell
  share one QML scene and can reach each other's objects, which is no place for decrypted
  passwords. The plugin half only checks that `install.sh` has been run.
- **Nothing shown before you unlock.** While locked, the backend does not even send the app the
  names of your entries. The unlock is tied to that one app window and ends when it closes.
- **One scan, two clocks.** A fingerprint (or your password) gives full access for **2 minutes**.
  After that the window still shows what is in it, but revealing, copying and editing ask for
  another scan, which restarts the two minutes everywhere rather than for one entry. **5 minutes**
  after the last scan the window locks completely: what was on screen is dropped, the backend
  stops sending names, and clicking anywhere asks to unlock again.
- **Every write is checked.** After saving to iCloud the app syncs and reads the change back,
  and only then says it is done. An edit that would change anything beyond what you asked for
  is refused before it is sent.
- **Encrypted at rest.** Your synced vault and sign-in are encrypted in `~/.config/icp` with a
  key kept in your login keyring. If there is no keyring the backend stops rather than falling
  back to a plain key file. To make a passphrase the at-rest boundary instead:
  `~/.local/share/pear-passwords/venv/bin/icp passphrase`. The derived key is held only by a
  private runtime agent after you unlock; it is never written to `~/.config/icp`, and `icp lock`
  or the agent timeout requires the passphrase again.
- **What leaves your computer.** Requests go to Apple only. Apple's sign-in needs anisette data,
  a device fingerprint normally generated by macOS. The sign-in helper,
  [anisette-v3-server](https://github.com/Dadoum/anisette-v3-server), provides it in a podman
  container. It listens on `127.0.0.1` only, and its image is pinned by digest, so a changed
  image can't be pulled in silently. It is third-party code that isn't part of this repository;
  its source is at the link above.
- **Locked dependencies.** Every Python package, including the build tool and every
  transitive dependency, is pinned to an exact version and installed with
  `pip --require-hashes` from `backend/requirements.lock` and `backend/build-requirements.lock`.
  Only prebuilt wheels are accepted, and the backend itself is built with the locked
  `setuptools` offline (`--no-build-isolation --no-index`), so an install can't pull in
  anything that isn't in the locks.
- **Nothing serves your passwords.** The window asks the backend one command at a time, and
  every command checks the unlock. The only listeners are the sign-in helper below and, only if
  you set a passphrase, a key agent that holds the derived key in memory behind a socket in your
  private runtime directory (`$XDG_RUNTIME_DIR`, mode 0700) and forgets it after an idle timeout.
- **The touchpad, read-only.** To stop a coasting scroll the moment your fingers land, a small
  reader opens the touchpad device (only a device named as a touchpad, never the keyboard) and
  prints the single word `touch`. Without access to the device it exits quietly and scrolling
  simply doesn't stop on touch.
- **Screen capture, only when you ask.** **Scan QR code** captures just the area you drag
  around, decodes it, and keeps nothing. It never runs on its own.
- **Same-user limits.** Like any desktop password manager on Linux, it cannot protect you from
  other programs running as your own user.

## Uninstall

```bash
./uninstall.sh            # keeps your synced passwords and this computer's sign-in
./uninstall.sh --purge    # also deletes them (asks first)
omarchy plugin remove io.github.dragosol.pear-passwords
```

## Updating the dependency locks

For maintainers. Change the exact pins in `backend/pyproject.toml`, then regenerate both locks
with hashes for every published file, so installs work on any architecture:

```bash
cd backend
uv pip compile pyproject.toml --universal --python-version 3.10 --generate-hashes \
    --no-header --no-annotate -o requirements.lock
echo "setuptools==<version>" | uv pip compile - --universal --python-version 3.10 \
    --generate-hashes --no-header --no-annotate -o build-requirements.lock
```

Keep the two comment lines at the top of each lock, then run `./install.sh` and the tests.

## Credits

The backend builds on the original Linux iCloud sync backend by
[Sankarsh Makam](https://github.com/Sank6) (MIT). Anisette data comes from
[anisette-v3-server](https://github.com/Dadoum/anisette-v3-server) by Dadoum.

## License

MIT, see [LICENSE](LICENSE).
