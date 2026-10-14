# system/

Everything the root install step puts outside `$HOME`. The values of every path and name are in
`paths.env` (shell) and `backend/icp/daemon/paths.py` (Python); a test keeps them equal.

| Path in this repo | Installed as | Owner |
|---|---|---|
| `paths.env` | read by the scripts below (not installed) | shared |
| `units/pear-passwordsd.socket`, `units/pear-passwordsd.service` | `/etc/systemd/system/` | the daemon |
| `sysusers.d/pear-passwords.conf` | `/etc/sysusers.d/pear-passwords.conf` | the daemon |
| `tmpfiles.d/pear-passwords.conf` | `/etc/tmpfiles.d/pear-passwords.conf` | the daemon |
| `libexec/pear-passwordsd` | `$P/libexec/pear-passwordsd` (ABI check, then the daemon; exit 78 on a Python minor bump) | the daemon |
| `libexec/pear-autofill-host` | `$P/libexec/pear-autofill-host` (`exec $P/libexec/pear-exec autofill`, browser arguments dropped) | the autofill host |
| `bin/pear-passwords-autofill` | `/usr/local/bin/pear-passwords-autofill` (opt-in `register` / `unregister`, runs as the user) | the autofill host |
| `native-messaging/io.github.dragosol.pearpasswords.json.in` | not installed; the template `register` fills in | the autofill host |
| `install-root.sh`, `uninstall-root.sh`, `lib/files.sh` | run from the stage; `uninstall-root.sh` also as `$P/libexec/uninstall-root` (generated at install time with `paths.env` and `lib/files.sh` inlined, so it runs with nothing else from the stage; the receipt records the generated file's hash) | the installer |
| `lib/user-files.sh` | not installed; the shared `RELEASED_USER` list `install.sh` and `uninstall.sh` use to retire 1.x files in your home by hash | the installer |
| (generated) | `$P/VERSION`, root 0644: `version=<v>` and `sums=<sha256 of SHA256SUMS>`, read by `install.sh --app-only` and the plugin to tell whether the installed snapshot is current | the installer |

Also from the stage: `native/pear-exec.c` (built to `$P/libexec/pear-exec`, root:pear-client
2755), `app/fonts.conf` (`$P/etc/fonts.conf`), `app/io.github.dragosol.PearPasswords.desktop`
(`/usr/local/share/applications/`) and every other file under `app/` (`$P/app`, root 0644,
with `Ui` and `Commons` linked to `/usr/share/omarchy/shell`).

The polkit policy is in `polkit/` and is installed as
`/usr/share/polkit-1/actions/io.github.dragosol.pearpasswords.policy`. `pear-exec` is built from
`native/pear-exec.c`.

No browser native-messaging manifest is ever written by an installer: autofill is opt-in,
per browser, with `pear-passwords-autofill register` (README, "Autofill (bring your own
extension)").
