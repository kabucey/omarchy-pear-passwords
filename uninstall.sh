#!/usr/bin/env bash
# Removes what install.sh put in your home, then tells you the one root command that removes
# the system part. Run it before that command: it unregisters autofill from your browsers with
# the pear-passwords-autofill command, which the root uninstall removes.
#
# Only files whose bytes are what Pear wrote are removed (system/lib/user-files.sh); anything
# you changed is listed and kept. The anisette helper's device identity (the icp-anisette
# volume) and your 1.x data in ~/.config/icp* are kept unless you pass --purge, because
# deleting them signs this computer out and Apple asks for a verification code next time.
#
#   ./uninstall.sh            keeps your passwords on this computer and its Apple sign-in
#   ./uninstall.sh --purge    also deletes them (asks first)
set -euo pipefail
[ "$(id -u)" -ne 0 ] || { echo "run this as your own user, not root" >&2; exit 1; }

purge=0
case "${1:-}" in
  "") ;;
  --purge) purge=1 ;;
  *) echo "usage: ./uninstall.sh [--purge]" >&2; exit 64 ;;
esac

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=system/paths.env
. "$here/system/paths.env"
# shellcheck source=system/lib/user-files.sh
. "$here/system/lib/user-files.sh"

# Browser registrations first: only manifests the register command wrote and still match its
# receipt are removed (the autofill host's command decides; this only asks it to).
if [ -x "$AUTOFILL_REGISTER_BIN" ]; then
  "$AUTOFILL_REGISTER_BIN" unregister --all || echo "warning: could not unregister autofill" >&2
fi

kept=()
anisette_unit="$PP_UNITS/pear-passwords-anisette.service"
if [ -e "$anisette_unit" ] || [ -L "$anisette_unit" ]; then
  if pp_user_ours "$anisette_unit" "$here/systemd/pear-passwords-anisette.service"; then
    systemctl --user disable --now pear-passwords-anisette.service 2>/dev/null || true
    rm -f -- "$anisette_unit"
  else
    kept+=("$anisette_unit")
  fi
fi
# 1.x leftovers, by hash: the sync units and the launcher (2.0's launcher is the system one).
for f in "$PP_UNITS/pear-passwords-sync.timer" "$PP_UNITS/pear-passwords-sync.service" \
         "$PP_LAUNCHER_1X"; do
  [ -e "$f" ] || [ -L "$f" ] || continue
  if pp_user_ours "$f"; then
    [[ $f == *.desktop ]] || systemctl --user disable --now "${f##*/}" 2>/dev/null || true
    rm -f -- "$f"
  else
    kept+=("$f")
  fi
done
systemctl --user daemon-reload 2>/dev/null || true
# install.sh's own build products: the 1.x virtualenv and window copy, and the stage.
rm -rf -- "$PP_DATA_1X/venv" "$PP_DATA_1X/app" "$PP_DATA_1X/app.new" "$PP_DATA_1X/app.old" \
          "$PP_STAGE_CACHE"
[ ! -d "$PP_DATA_1X" ] || rmdir -- "$PP_DATA_1X" 2>/dev/null || kept+=("$PP_DATA_1X (holds other files)")
# The locally built anisette image is a build artefact, not data: anisette/build.sh makes it
# again. The icp-anisette volume holding the device identity is left alone unless --purge.
podman image rm -f $(podman images --filter reference='localhost/pear-passwords-anisette' \
                       --format '{{.ID}}' 2>/dev/null) >/dev/null 2>&1 || true

if ((${#kept[@]})); then
  echo "Left in place, not a file Pear installed (or changed since):"
  printf '  %s\n' "${kept[@]}"
fi
echo "Removed Pear Passwords from your home."

if [ "$purge" -eq 1 ]; then
  read -r -p "Also delete this computer's Apple sign-in identity and your 1.x data in ~/.config/icp*? [y/N] " yn
  if [ "$yn" = "y" ] || [ "$yn" = "Y" ]; then
    podman volume rm -f icp-anisette >/dev/null 2>&1 || true
    rm -rf -- "$HOME/.config/icp" "$HOME"/.config/icp.v1-backup-*
    echo "Deleted the device identity and the 1.x data."
  fi
fi

echo
if [ -x "$UNINSTALL_ROOT" ]; then
  echo "To remove the system part, run:"
  if [ "$purge" -eq 1 ]; then
    echo "  sudo $UNINSTALL_ROOT --purge $(id -u)     (also deletes your vault in $STATE_DIR)"
  else
    echo "  sudo $UNINSTALL_ROOT                     (keeps your vault; add --purge $(id -u) to delete it)"
  fi
fi
echo "Then: omarchy plugin remove io.github.dragosol.pear-passwords"
