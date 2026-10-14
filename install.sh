#!/usr/bin/env bash
# Pear Passwords installer, the part that runs as you. It never uses sudo and refuses to run as
# root. 2.0 keeps your passwords in a small system service (pear-passwordsd, under its own
# user), so the install has two halves: this script, then one root command it prints at the end.
#
# What this script does:
#   - builds the anisette sign-in helper from pinned source and enables its user unit
#     (~/.config/systemd/user/pear-passwords-anisette.service), as 1.x did;
#   - stages what the root command installs into ~/.cache/pear-passwords/stage: exactly the
#     files SHA256SUMS lists, copied from this checkout, plus the hash-locked wheels
#     (downloaded with pip --require-hashes, wheels only). Root never downloads anything;
#   - retires what 1.x put in your home, file by file and only on an exact hash match
#     (system/lib/user-files.sh): the 2-hourly sync units, the 1.x launcher once the 2.0 one
#     exists, and the 1.x virtualenv once your passwords have moved into 2.0;
#   - prints the root command, with the hash of SHA256SUMS that you check against the release
#     notes. Nothing here runs anything as root.
# It never touches ~/.config/icp (your 1.x vault): the 2.0 window moves it, once, when you ask.
#
# No browser is set up for autofill. That is opt-in, per browser, with your own extension:
# `pear-passwords-autofill register` (README, "Autofill (bring your own extension)").
#
#   ./install.sh             everything above
#   ./install.sh --stage     only stage and print the root command (no anisette, no cleanup)
#   ./install.sh --app-only  only report whether the system part is installed and matches this
#                            checkout (exit 0), is missing (3) or is another version (4).
#                            Writes nothing except retiring hash-matched 1.x files once 2.0 is
#                            installed. (The plugin makes the same VERSION comparison itself,
#                            read-only, when the shell loads; it does not run this script.)
#
# Re-run it after `omarchy plugin update`, then run the root command it prints again.
set -euo pipefail

app_only=0
stage_only=0
case "${1:-}" in
  "") ;;
  --app-only) app_only=1 ;;
  --stage) stage_only=1 ;;
  *) echo "usage: ./install.sh [--stage|--app-only]" >&2; exit 64 ;;
esac

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=system/paths.env
. "$here/system/paths.env"
# shellcheck source=system/lib/user-files.sh
. "$here/system/lib/user-files.sh"
units="$PP_UNITS"
stage="$PP_STAGE_CACHE/stage"

say()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -ne 0 ] || die "run this as your own user, not root - it prints the one command that needs root"

needed="sha256sum podman systemctl"
[ "$stage_only" -eq 1 ] && needed="sha256sum"
[ "$app_only" -eq 1 ] && needed="quickshell"
for cmd in $needed; do
  command -v "$cmd" >/dev/null 2>&1 || die "'$cmd' is required but not installed"
done
# Root builds the venv with /usr/bin/python3, so the wheels must be fetched for that Python,
# not whichever python3 is first on your PATH.
[ "$app_only" -eq 1 ] || [ -x /usr/bin/python3 ] || die "/usr/bin/python3 is required"

version="$(sed -n 's/^ *"version": *"\([0-9][0-9.]*\)".*/\1/p' "$here/manifest.json" | head -n 1)"
sums_hash="$(sha256sum < "$here/SHA256SUMS" | cut -c1-64)"

# Is the system part installed, and is it this exact snapshot? Everything checked here is
# world-readable: pear-exec's owner and mode, and $P/VERSION written by the root step.
system_state() {
  local st
  [ -f "$PEAR_EXEC" ] && [ ! -L "$PEAR_EXEC" ] || { echo missing; return; }
  st="$(stat -c '%u %G %a' "$PEAR_EXEC")"
  [ "$st" = "0 $CLIENT_GROUP 2755" ] || { echo missing; return; }
  if [ "$(cat "$PREFIX/VERSION" 2>/dev/null)" = "$(printf 'version=%s\nsums=%s' "$version" "$sums_hash")" ]; then
    echo current
  else
    echo other
  fi
}

root_command() {
  cat <<CMD
sudo sh -c 'set -eu; h=\$(getent passwd "\${SUDO_USER:?run this with sudo}" | cut -d: -f6); s=\$(mktemp -d /root/pear-stage.XXXXXX); trap "rm -rf \\"\$s\\"" EXIT; cp -rT --no-preserve=all "\$h/.cache/pear-passwords/stage" "\$s"; cd "\$s"; echo "$sums_hash  SHA256SUMS" | sha256sum -c --strict --quiet; sha256sum -c --strict --quiet SHA256SUMS; sh ./system/install-root.sh "\$s"'
CMD
}

if [ "$app_only" -eq 1 ]; then
  state="$(system_state)"
  if [ "$state" != missing ]; then
    pp_retire_1x
  fi
  case "$state" in
    current) echo "Pear Passwords $version is installed." ; exit 0 ;;
    other)   echo "Pear Passwords is installed, but not version $version: run ./install.sh in $here, then the root command it prints." ; exit 4 ;;
    *)       echo "Pear Passwords' system part is not installed: run ./install.sh in $here, then the root command it prints." ; exit 3 ;;
  esac
fi

# --- the checkout ----------------------------------------------------------------------------
# SHA256SUMS is what root will check the stage against. A checkout whose files do not match it
# (a local edit, a half-applied update) would fail there; say so here instead.
(cd "$here" && sha256sum -c --strict --quiet SHA256SUMS) \
  || die "this checkout does not match its SHA256SUMS (a local change, or an interrupted update)"

if [ "$stage_only" -eq 0 ]; then
say "Building the anisette server from pinned source"
# The sign-in helper is third-party code (Dadoum/anisette-v3-server). The published image on
# Docker Hub has no provenance labels and ships a binary built elsewhere, so it is built here
# instead, from the one upstream commit pinned in anisette/Containerfile. Takes a couple of
# minutes the first time; after that the image is reused. See docs/anisette-provenance.md.
anisette_rev="$(sed -n 's/^ARG ANISETTE_REV=\([0-9a-f]\{40\}\)$/\1/p' "$here/anisette/Containerfile")"
[ -n "$anisette_rev" ] || die "could not read the pinned anisette revision from anisette/Containerfile"
# Pear's patches to that source (anisette/patches/) are part of the tag, so an image built
# before a patch changed is rebuilt rather than reused.
anisette_patches="$("$here/anisette/patch-id.sh")"
anisette_image="localhost/pear-passwords-anisette:$anisette_rev-$anisette_patches"
# A unit pointing at a tag nobody builds would fail at start with a bare "image not known".
grep -qF "$anisette_image" "$here/systemd/pear-passwords-anisette.service" \
  || die "systemd/pear-passwords-anisette.service does not run $anisette_image"
anisette_rebuilt=0
if [ "$(podman image inspect --format '{{index .Labels "org.opencontainers.image.revision"}} {{index .Labels "io.github.dragosol.pear-passwords.patches"}}' \
        "$anisette_image" 2>/dev/null)" = "$anisette_rev $anisette_patches" ]; then
  say "Already built at ${anisette_rev:0:12} with patches $anisette_patches, reusing it"
else
  "$here/anisette/build.sh" "$anisette_rev"
  anisette_rebuilt=1
fi

say "Installing the sign-in helper"
# The daemon asks it for anisette data on 127.0.0.1:6969 while you sign in or sync. A unit of
# the same name that is not one Pear shipped is yours, and stays.
mkdir -p "$units"
anisette_unit="$units/pear-passwords-anisette.service"
if [ -e "$anisette_unit" ] && ! pp_user_ours "$anisette_unit" "$here/systemd/pear-passwords-anisette.service"; then
  warn "kept $anisette_unit: it is not one Pear installed"
else
  install -m 644 "$here/systemd/pear-passwords-anisette.service" "$units/"
fi
systemctl --user daemon-reload
systemctl --user enable --now pear-passwords-anisette.service
# A unit already running keeps the image it started with until it restarts.
if [ "$anisette_rebuilt" -eq 1 ]; then
  systemctl --user try-restart pear-passwords-anisette.service
fi
fi

# --- the stage -------------------------------------------------------------------------------
say "Staging $version for the system step in $stage"
mkdir -p "$PP_STAGE_CACHE"
chmod 700 "$PP_STAGE_CACHE"
rm -rf "$stage.new"
mkdir -m 700 "$stage.new"
# Exactly the listed files, so nothing else in this checkout (caches, build output, your own
# files) ever reaches root.
cut -c67- "$here/SHA256SUMS" | while IFS= read -r f; do
  mkdir -p "$stage.new/$(dirname "$f")"
  cp -- "$here/$f" "$stage.new/$f"
done
cp -- "$here/SHA256SUMS" "$stage.new/SHA256SUMS"

say "Downloading the locked wheels"
# A throwaway pip next to the stage, made by the same /usr/bin/python3 root uses, so the wheels
# match its version and platform. --require-hashes checks every one against the lock files;
# root checks them again before installing.
pipenv="$PP_STAGE_CACHE/pip"
pp_pip_venv "$pipenv"
"$pipenv/bin/python" -m pip download --quiet --disable-pip-version-check --no-input \
  --require-hashes --only-binary :all: --no-deps -d "$stage.new/wheels" \
  -r "$stage.new/backend/requirements.lock" -r "$stage.new/backend/build-requirements.lock"

(cd "$stage.new" && sha256sum -c --strict --quiet SHA256SUMS) || die "the stage does not match SHA256SUMS"
[ -z "$(find "$stage.new" -type l)" ] || die "the stage contains symlinks"
rm -rf "$stage"
mv "$stage.new" "$stage"

if [ "$stage_only" -eq 0 ]; then
  say "Retiring what 1.x installed in your home"
  pp_retire_1x
fi

state="$(system_state)"
echo
case "$state" in
  current) echo "The system part is already installed at exactly this version. Nothing else to do."
           echo "To repair or reinstall it anyway, the same root command as for an install:" ;;
  other)   echo "One step left: update the system part. Run this command (it asks for your password):" ;;
  *)       echo "One step left: install the system part. Run this command (it asks for your password):" ;;
esac
cat <<NOTE

$(root_command)

It copies the stage into a fresh directory under /root, checks it against this hash of
SHA256SUMS, and runs system/install-root.sh from that copy:

    $sums_hash

Check that the hash matches the one in the release notes for $version, at
https://github.com/dragosol/omarchy-pear-passwords/releases - it is what proves the files
root installs are the reviewed ones. Then open Pear Passwords from the launcher.
NOTE
if [ "$state" = missing ] && [ -e "$PP_LAUNCHER_1X" ]; then
  cat <<NOTE

The 1.x launcher stays until the 2.0 one exists. After the root command, run
./install.sh --app-only once to remove it (moving your vault into 2.0 removes it too).
NOTE
fi
