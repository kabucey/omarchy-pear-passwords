#!/bin/sh
# Pear Passwords 2: the root install step.
#
# Run only through the paste-ready command install.sh prints (README "Install"), which copies
# ~/.cache/pear-passwords/stage into a fresh /root/pear-stage.XXXXXX, checks SHA256SUMS against
# the hash published in the release notes, checks every staged file against SHA256SUMS, and
# then runs this script from that root-owned copy:
#
#   sh ./system/install-root.sh <stage>
#
# What it does, in order. Nothing is written before every check has passed:
#   1. checks the stage again (no symlinks, nothing SHA256SUMS does not list but wheels);
#   2. checks every destination (system/lib/files.sh): each one is free or already ours, no
#      same-named unit, drop-in or policy shadows ours, the pear-passwords user and the
#      pear-client group are what Pear would create, and $P has a receipt if it exists;
#   3. creates the pear-passwords user and the empty pear-client group (systemd-sysusers) and
#      /var/lib/pear-passwords (systemd-tmpfiles);
#   4. builds the venv offline: pip --no-index from the staged wheels, hash-checked against
#      backend/requirements.lock, wheels only, then the backend itself with no build isolation;
#   5. compiles pear-exec from native/pear-exec.c and installs it root:pear-client 2755;
#   6. installs the app, units, policy, wrappers, fonts.conf and the launcher, each written
#      beside its destination and renamed into place; swaps the new venv in;
#   7. removes files an older 2.x installed that this one no longer ships (only if unchanged)
#      and the 1.x polkit action (only if it is byte-for-byte a released copy);
#   8. writes the receipt, reloads systemd and enables the socket.
# A receipt naming everything a step may write is on disk before that step runs, so a run
# interrupted anywhere can be re-run (or uninstalled) and proves ownership from it.
#
# Re-running the same command with a newer stage upgrades in place. It never touches
# /var/lib/pear-passwords (your vault) and never fetches anything from the network. Not used
# anywhere: chattr, sudoers, /tmp, PID files, curl|sh.
set -eu

#--- stage-only begin
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$here/paths.env"
. "$here/lib/files.sh"
#--- stage-only end

pp_init_mode

[ $# -eq 1 ] || pp_die "usage: sh ./system/install-root.sh <stage directory>"
stage=$(CDPATH= cd -- "$1" && pwd) || pp_die "no stage at $1"
[ "$stage" != / ] || pp_die "the stage cannot be /"

pp_say "Checking the stage"
pp_stage_verify "$stage"
version=$(sed -n 's/^ *"version": *"\([0-9][0-9.]*\)".*/\1/p' "$stage/manifest.json" | head -n 1)
[ -n "$version" ] || pp_die "manifest.json has no version"

# Work files live inside the stage (root's own copy), never in /tmp.
work=$(mktemp -d "$stage/.work.XXXXXX")
trap 'rm -rf "$work"' EXIT

# --- prerequisites ---------------------------------------------------------------------------
if [ "$PP_TEST" -eq 0 ]; then
  for cmd in systemd-sysusers systemd-tmpfiles systemctl install sha256sum find; do
    command -v "$cmd" >/dev/null 2>&1 || pp_die "'$cmd' is required"
  done
  [ -x /usr/bin/python3 ] || pp_die "/usr/bin/python3 is required"
  [ -x /usr/bin/quickshell ] || pp_warn "/usr/bin/quickshell is missing: the window will not open"
  [ -d "$PP_OMARCHY_SHELL/Ui" ] && [ -d "$PP_OMARCHY_SHELL/Commons" ] \
    || pp_warn "Omarchy's shell components were not found in $PP_OMARCHY_SHELL"
fi
command -v cc >/dev/null 2>&1 || pp_die "install gcc: pear-exec is compiled from source here (pacman -S gcc)"

seal_was_installed=0
! pp_exists "$UNIT_DIR/$SEAL_SOCKET_UNIT" || seal_was_installed=1

# --- what will be installed ------------------------------------------------------------------
pp_table "$stage" "$work" > "$work/table"
missing=$(pp_missing_sources "$stage" "$work" "$work/table")
[ -z "$missing" ] || pp_die "the stage is incomplete (is this a 2.x checkout?): $(echo $missing)"

pp_say "Compiling pear-exec"
cc -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=3 -fPIE -pie -Wl,-z,relro,-z,now \
   -o "$work/pear-exec" "$stage/native/pear-exec.c"

# The installed uninstaller is one self-contained file: paths.env and files.sh are inlined, so
# `sudo $P/libexec/uninstall-root` reads nothing that is not root-owned and in the receipt.
{
  printf '#!/bin/sh\n# Installed copy of system/uninstall-root.sh %s, with paths.env and lib/files.sh inlined.\n' "$version"
  grep -E '^[A-Z][A-Z0-9_]*=' "$stage/system/paths.env"
  cat "$stage/system/lib/files.sh"
  sed -e '1d' -e '/^#--- stage-only begin/,/^#--- stage-only end/d' "$stage/system/uninstall-root.sh"
} > "$work/uninstall-root"

# What install.sh --app-only (and the plugin) compare against: this exact snapshot.
printf 'version=%s\nsums=%s\n' "$version" "$(pp_sha256 "$stage/SHA256SUMS")" > "$work/VERSION"

# --- check everything before any write ------------------------------------------------------
pp_load_receipt "$work/receipt.old"
pp_check_all "$work/table" > "$work/problems"
if [ -s "$work/problems" ]; then
  echo "Not installing: these paths are in the way." >&2
  sed 's/^/  /' "$work/problems" >&2
  echo "Nothing was changed. Move them aside if they are not needed, then run the command again." >&2
  exit 1
fi

# Before the first write: a receipt naming everything this run may write. An interrupted run
# (Ctrl-C, a failed pip, a closed terminal) leaves it behind, and the next run accepts $P.
pp_planned_receipt "$work/table" > "$work/receipt.planned"
pp_write_receipt "$work/receipt.planned"
# A failed earlier run's half-built venv, or the old one a swap without exch(1) set aside.
# Removed only now: $P is proven ours (the checks above passed with a receipt), and these
# are names only this script uses.
rm -rf -- "$(pp_d "$VENV.new")" "$(pp_d "$VENV.old")"
# And any <dest>.pp-new an interrupted copy left (each one checked above to be a prefix of the
# staged file, owned by root).
pp_clean_pp_new "$work/table"

# --- identities ------------------------------------------------------------------------------
pp_say "Creating the pear-passwords user and the pear-client group"
pp_install_dest "$work/table" "$SYSUSERS_CONF"
pp_install_dest "$work/table" "$TMPFILES_CONF"
pp_sys systemd-sysusers "$SYSUSERS_CONF"
pp_sys systemd-tmpfiles --create "$TMPFILES_CONF"
# sysusers may have created them just now; the group must still have no members.
pp_check_identities > "$work/problems"
[ ! -s "$work/problems" ] || pp_die "$(cat "$work/problems")"
if [ "$PP_TEST" -eq 0 ]; then
  [ -n "$(pp_getent group "$CLIENT_GROUP")" ] || pp_die "systemd-sysusers did not create $CLIENT_GROUP"
  [ -n "$(pp_getent passwd "$SERVICE_USER")" ] || pp_die "systemd-sysusers did not create $SERVICE_USER"
fi

# --- the venv, offline -----------------------------------------------------------------------
new=$(pp_d "$VENV.new")
if [ "$PP_TEST" -eq 0 ]; then
  pp_say "Building the backend offline from the staged wheels"
  mkdir -p "$work/tmp"
  pip_install() {
    TMPDIR="$work/tmp" "$new/bin/python" -I -m pip install --isolated --no-cache-dir \
      --disable-pip-version-check --no-input --quiet --no-index "$@"
  }
  /usr/bin/python3 -I -m venv "$new"
  pip_install --find-links "$stage/wheels" --require-hashes --only-binary :all: --no-deps \
    -r "$stage/backend/requirements.lock"
  pip_install --find-links "$stage/wheels" --require-hashes --only-binary :all: --no-deps \
    -r "$stage/backend/build-requirements.lock"
  pip_install --no-build-isolation --no-deps "$stage/backend"
  TMPDIR="$work/tmp" "$new/bin/python" -I -m pip check --isolated --disable-pip-version-check \
    >/dev/null || pp_die "the installed packages do not agree with the lock files"
else
  # Tests: a stand-in tree with the same shape, so the receipt and swap logic run for real.
  mkdir -p "$new/bin" "$new/lib/site-packages/icp"
  ln -s /usr/bin/python3 "$new/bin/python"
  cp "$stage/backend/icp/__init__.py" "$new/lib/site-packages/icp/__init__.py"
  printf '#!%s/bin/python\nprint()\n' "$new" > "$new/bin/icp"
  printf 'home = /usr/bin\ncommand = /usr/bin/python3 -m venv %s\n' "$new" > "$new/pyvenv.cfg"
fi
# Scripts and pyvenv.cfg name the directory they were built in; they will live at $VENV.
for f in "$new"/bin/* "$new/pyvenv.cfg"; do
  [ -f "$f" ] && [ ! -L "$f" ] || continue
  if grep -qF "$new" "$f"; then
    sed -i "s|$new|$(pp_d "$VENV")|g" "$f"
  fi
done
if [ "$PP_TEST" -eq 0 ]; then
  chown -R root:root "$new"
fi
chmod -R go-w "$new"
pp_test_stop venv

# --- install ---------------------------------------------------------------------------------
pp_say "Installing into $PREFIX"
pp_install_table "$work/table"

# Before the swap, the receipt names both venv trees as ours, so an interruption between the
# swap and the final receipt leaves nothing under $P the next run cannot account for.
{
  cat "$work/receipt.planned"
  pp_manifest "$VENV.new" | awk -F "$PP_TAB" -v OFS="$PP_TAB" -v n="$VENV.new/" -v v="$VENV/" \
    'index($3, n) == 1 { $3 = v substr($3, length(n) + 1) } { print }'
} | LC_ALL=C sort -u > "$work/receipt.swap"
pp_write_receipt "$work/receipt.swap"

# Swap the venv in. exch(1) (util-linux 2.40+) swaps the two names in one rename; without it
# the old venv is moved aside first, which leaves a moment with no venv (the socket queues).
old=$(pp_d "$VENV")
if [ -d "$old" ] && command -v exch >/dev/null 2>&1; then
  exch -- "$new" "$old"
  rm -rf -- "$new"
elif [ -d "$old" ]; then
  rm -rf -- "$old.old"
  mv -T -- "$old" "$old.old"
  mv -T -- "$new" "$old"
  rm -rf -- "$old.old"
else
  mv -T -- "$new" "$old"
fi
pp_test_stop swap

# Files an earlier 2.x installed that this version no longer ships. The checks above already
# refused if any of them was edited.
pp_new_receipt "$work/table" > "$work/receipt.new"
cut -f3 "$work/receipt.new" > "$work/paths.new"
awk -F "$PP_TAB" 'NR == FNR { keep[$0] = 1; next } !($3 in keep)' \
  "$work/paths.new" "$PP_OLD" > "$work/stale"
: > "$work/kept"
pp_remove_entries "$work/stale" "$work/kept"
[ ! -s "$work/kept" ] || pp_warn "kept, changed since installed: $(cut -f3 "$work/kept" | tr '\n' ' ')"

pp_remove_legacy_policy

# The receipt: what this install wrote. The next upgrade and uninstall-root only touch files
# that still match it.
pp_write_receipt "$work/receipt.new"

pp_sys systemctl daemon-reload
# Gate G1 fallback: the root seal socket runs only when the daemon unit asks for it. An
# upgrade from a release that used it turns it off again.
if pp_seal_service_selected "$stage/system/units/$SERVICE_UNIT"; then
  pp_sys systemctl enable --now "$SEAL_SOCKET_UNIT"
elif [ "$seal_was_installed" = 1 ]; then
  pp_sys systemctl disable --now "$SEAL_SOCKET_UNIT" 2>/dev/null || true
fi
pp_sys systemctl enable --now "$SOCKET_UNIT"
# An upgrade must not leave the old daemon serving with the old code. This locks anyone who
# had Pear open; the window shows "Locked" and one click unlocks again.
pp_sys systemctl try-restart "$SERVICE_UNIT"

cat <<DONE

Pear Passwords $version is installed. Open it from the launcher: search "Pear Passwords".
To remove it later:  sudo $UNINSTALL_ROOT
DONE
