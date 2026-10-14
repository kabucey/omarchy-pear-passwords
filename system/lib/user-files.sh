# shellcheck shell=bash
# Pear Passwords 2: what the user half (install.sh, uninstall.sh) may remove from your home,
# and how it tells a file Pear wrote from one you wrote. Sourced after system/paths.env.
#
# 1.x installed systemd user units and a launcher into your home. 2.0 replaces them, and
# removes one only if its bytes are exactly a version 1.x shipped (RELEASED_USER below). A file
# you edited, or one with the same name that is not Pear's, is listed and left alone. The
# launcher embeds your home directory, so it is compared with that one path replaced by
# @DATA@.
#
# Nothing here touches ~/.config/icp (the 1.x vault): the migration in the 2.0 window owns it.

PP_DATA_1X="$HOME/.local/share/pear-passwords"
PP_UNITS="$HOME/.config/systemd/user"
PP_LAUNCHER_1X="$HOME/.local/share/applications/pear-passwords.desktop"
PP_STAGE_CACHE="$HOME/.cache/pear-passwords"

# sha256 of every released copy, by file name: every 1.x commit, and each 2.x change since.
RELEASED_USER="
168fb5f9f75df0b5489bf548f76131ef44af07c7efe4d2cc5b877985d2c09355 pear-passwords-sync.service
262574cf2494701fafd6a19d042cc3eccd320259b03c54b1aba02aa5b10a72a4 pear-passwords-sync.service
38ebb0fe9bb7f71d0bcc388ec708d5c6128dc068322316f4b0101785f0bd850e pear-passwords-sync.service
7d6b5a35bcbb9c820339e2f2c8dfc5a5e091e6ba1e757f8195e1883b6fda3387 pear-passwords-sync.service
332dbe2873375cb56573c7647b217f88724475fa056def03d34ad95a76cf1082 pear-passwords-sync.timer
4ec8dc071211292f6a51c4367a032e2bf08c5810e948cb0f70d14c16650cf546 pear-passwords-sync.timer
d06ba8e79d61ce49831c425cb01a2dd4b0c80d1980a25f9ee2f5748a2bafba11 pear-passwords-sync.timer
17c95a02b27af6ae8a245f94c302422f3104537b9a0cd9cc221c18e8b4f5d916 pear-passwords-anisette.service
c6d76ad886446638daee70ac8140ceaa8139d028b0550053364e12b6c4735447 pear-passwords-anisette.service
1af21f03ad889d583db7c5af22bdaa62f83743f38eb50a18d27cd74fc16838e6 pear-passwords-anisette.service
720986736414f5ffc6ae8119650ce72bb85ebdba0c0814ed07514d92952cac53 pear-passwords.desktop
500f1ad818d777801e2d7929dc8aa90d454fd1faf835ebee5788b36c3554ac70 pear-passwords.desktop
9fea786026bfbfa8c9cc3146bd93d8ddb31fcc9e73b88e26c3865fd4442d9c1a pear-passwords.desktop
282145fd9d9d173f38c2e5a68b2e17bcfc22907d8cc5105cc1b25769a9803065 pear-passwords.desktop
"

pp_user_sha() { sha256sum < "$1" | cut -c1-64; }

# The launcher's hash with this user's data directory written as @DATA@, as in the template.
pp_launcher_sha() {
  /usr/bin/python3 -I -c '
import hashlib, sys
data = open(sys.argv[1], "rb").read().replace(sys.argv[2].encode(), b"@DATA@")
print(hashlib.sha256(data).hexdigest())' "$1" "$PP_DATA_1X"
}

# pp_user_ours FILE [SHIPPED]: FILE is a regular file whose bytes are a released copy of its
# name, or the file this checkout ships (SHIPPED).
pp_user_ours() {
  local f=$1 shipped=${2:-} name h
  [[ -f $f && ! -L $f ]] || return 1
  name=${f##*/}
  if [[ $name == pear-passwords.desktop ]]; then
    h=$(pp_launcher_sha "$f")
  else
    h=$(pp_user_sha "$f")
  fi
  [[ -n $shipped && -f $shipped && $h == "$(pp_user_sha "$shipped")" ]] && return 0
  grep -qxF "$h $name" <<< "$RELEASED_USER"
}

# pp_pip_venv DIR: install.sh's throwaway download venv at DIR, made by /usr/bin/python3 and
# rebuilt whenever it no longer matches it. After a Python minor upgrade the old venv's
# bin/python (a symlink) still runs, but looks for pip under the new lib/pythonX.Y and fails.
pp_pip_venv() {
  local d=$1 want have
  want=$(/usr/bin/python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
  have=$("$d/bin/python" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || true)
  if [[ ! -x $d/bin/python || $have != "$want" || ! -d $d/lib/python$want/site-packages/pip ]]; then
    rm -rf -- "$d"
    /usr/bin/python3 -m venv "$d"
  fi
}

# Has this user's vault been moved into 2.0? The daemon's state is not readable from here, so
# the sign is the migration's rename: a v1 backup exists and ~/.config/icp does not.
pp_migrated() {
  [[ ! -e $HOME/.config/icp ]] || return 1
  compgen -G "$HOME/.config/icp.v1-backup-*" >/dev/null
}

# pp_retire_1x: remove what 1.x installed in this home that 2.0 replaces. Prints what it kept.
#   - the 2-hourly sync units: always (2.0 syncs only inside the daemon, only while unlocked);
#   - the 1.x launcher: once the 2.0 launcher exists, so you are never left with none;
#   - the 1.x virtualenv and window copy: once your vault has been moved into 2.0, because
#     until then 1.3.2's agent may still be running from them (the migration asks it for the
#     key, so it must stay usable until then).
pp_retire_1x() {
  local u f kept=() changed=0
  for u in pear-passwords-sync.timer pear-passwords-sync.service; do
    f=$PP_UNITS/$u
    [[ -e $f || -L $f ]] || continue
    if pp_user_ours "$f"; then
      systemctl --user disable --now "$u" >/dev/null 2>&1 || true
      rm -f -- "$f"
      changed=1
      echo "Removed the 1.x unit $u"
    else
      kept+=("$f")
    fi
  done
  [[ $changed -eq 0 ]] || systemctl --user daemon-reload || true

  if [[ -e $PP_LAUNCHER_1X || -L $PP_LAUNCHER_1X ]]; then
    if ! pp_user_ours "$PP_LAUNCHER_1X"; then
      kept+=("$PP_LAUNCHER_1X")
    elif [[ -e $DESKTOP_FILE ]]; then
      rm -f -- "$PP_LAUNCHER_1X"
      command -v update-desktop-database >/dev/null 2>&1 \
        && update-desktop-database -q "${PP_LAUNCHER_1X%/*}" || true
      echo "Removed the 1.x launcher (the 2.0 one is installed)"
    else
      echo "Kept the 1.x launcher until the system step installs the 2.0 one."
    fi
  fi

  if [[ -d $PP_DATA_1X && ! -L $PP_DATA_1X ]]; then
    if pp_migrated; then
      rm -rf -- "$PP_DATA_1X/venv" "$PP_DATA_1X/app" "$PP_DATA_1X/app.new" "$PP_DATA_1X/app.old"
      rmdir -- "$PP_DATA_1X" 2>/dev/null || kept+=("$PP_DATA_1X (holds other files)")
      echo "Removed the 1.x backend and window ($PP_DATA_1X)"
    else
      echo "Kept 1.3.2's backend in $PP_DATA_1X until your passwords are moved into 2.0."
    fi
  fi

  if ((${#kept[@]})); then
    echo "Left in place, not a file Pear 1.x installed (or changed since):"
    printf '  %s\n' "${kept[@]}"
  fi
  return 0
}
