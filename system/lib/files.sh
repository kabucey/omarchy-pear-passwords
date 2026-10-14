# shellcheck shell=sh
# Pear Passwords 2: which files the root step puts on the system, and how to tell whether the
# file at one of those paths is ours. Sourced, after system/paths.env, by system/install-root.sh
# and system/uninstall-root.sh (the installed $P/libexec/uninstall-root carries an inlined copy).
#
# The Kernel Guard pattern. A path counts as ours only if it is a regular file (not a symlink)
# whose contents are byte-for-byte a file Pear put there:
#   - the file this stage is about to install (a harmless re-install),
#   - what the receipt says this machine's last install wrote, or
#   - one of the frozen RELEASED versions below (only the 1.x polkit action, which no receipt
#     ever recorded).
# Anything else at one of these paths belongs to someone else: install-root.sh stops before it
# changes anything, and uninstall-root.sh leaves the file where it is and lists it.
#
# POSIX sh on purpose (plus `local`, which bash, dash and busybox all have): the root command
# runs `sh ./system/install-root.sh`, and on a system where sh is not bash that must still mean
# the same thing. Every function declares its variables local; sh has no other scoping.
#
# Receipt ($INSTALL_RECEIPT, root 0600): one line per thing installed, tab-separated,
#   f <sha256> <path>     a regular file
#   l <target> <path>     a symlink
#   d - <path>            a directory Pear created (removed on uninstall only if empty)
# The venv is recorded file by file, so an edited or planted file inside it is noticed too.

PP_TAB=$(printf '\t')
PP_RECEIPT_HEADER='# pear-passwords install receipt v1'
PP_OMARCHY_SHELL=/usr/share/omarchy/shell

# sha256 of every /usr/share/polkit-1/actions/org.icp.unlock.policy that was ever handed out:
# the 3 Sep "iCloud Keychain for Linux" file (also what `pkexec install` in 1.3.x pointed at),
# and both revisions of polkit/org.icp.unlock.policy and of the README heredoc in 1.x (the two
# are byte-identical per revision). Frozen: 2.0 records what it installs in the receipt.
PP_RELEASED="
e52090fecadf25f26061ecd08b7cae0f2aa5c870cffcb91afd92038e5aa050cf /usr/share/polkit-1/actions/org.icp.unlock.policy
02e6dcf9a747c852d3da8cb8b186c1f54de002da1363e2c0150782eff71309ef /usr/share/polkit-1/actions/org.icp.unlock.policy
8c1bbb321bb0b4814ebe85dc29119e4c2afdc19ddfbb4ab3d22d91eb34073586 /usr/share/polkit-1/actions/org.icp.unlock.policy
"

pp_die()  { printf 'pear-passwords: %s\n' "$*" >&2; exit 1; }
pp_say()  { printf '==> %s\n' "$*"; }
pp_warn() { printf 'warning: %s\n' "$*" >&2; }

# --- mode ------------------------------------------------------------------------------------
# A real run must be root and writes /. PP_TEST_ROOT exists for backend/tests only: every
# system path is taken under that directory, nothing is chowned, the user database is read
# from its etc/passwd and etc/group, and commands that change the running system are written
# to its commands.log instead of being run. It is refused as root, so it can never point a
# real install somewhere else.
pp_init_mode() {
  PATH=/usr/bin:/usr/sbin:/bin:/sbin
  LC_ALL=C
  export PATH LC_ALL
  umask 022
  if [ -n "${PP_TEST_ROOT:-}" ]; then
    [ "$(id -u)" -ne 0 ] || pp_die "PP_TEST_ROOT is for the test suite and is refused as root"
    case $PP_TEST_ROOT in /?*) ;; *) pp_die "PP_TEST_ROOT must be an absolute path" ;; esac
    [ -d "$PP_TEST_ROOT" ] && [ ! -L "$PP_TEST_ROOT" ] || pp_die "PP_TEST_ROOT is not a directory"
    PP_D=${PP_TEST_ROOT%/}
    PP_TEST=1
  else
    [ "$(id -u)" -eq 0 ] || pp_die "run this as root (with sudo)"
    PP_D=
    PP_TEST=0
  fi
}

# pp_test_stop NAME: in test mode only, stop here when PP_TEST_STOP_AT=NAME, as a kill or a
# power cut would. A real run (root) never reads the variable.
pp_test_stop() {
  if [ "$PP_TEST" -eq 1 ] && [ "${PP_TEST_STOP_AT:-}" = "$1" ]; then
    printf 'test: stopped at %s\n' "$1" >&2
    exit 99
  fi
}

# The real location of a system path.
pp_d() { printf '%s%s' "$PP_D" "$1"; }

# Run a command that changes the running system (units, users, groups).
pp_sys() {
  if [ "$PP_TEST" -eq 1 ]; then
    printf '%s\n' "$*" >> "$PP_D/commands.log"
  else
    "$@"
  fi
}

# pp_getent passwd|group NAME: the entry, or nothing.
pp_getent() {
  if [ "$PP_TEST" -eq 1 ]; then
    [ -f "$PP_D/etc/$1" ] || return 0
    grep -m1 "^$2:" "$PP_D/etc/$1" || true
  else
    getent "$1" "$2" || true
  fi
}

# chown options for install(1); none in test mode, where nothing can be chowned.
pp_own() {
  if [ "$PP_TEST" -eq 1 ] || [ "$1" = - ]; then
    return 0
  fi
  printf -- '-o %s -g %s' "${1%%:*}" "${1#*:}"
}

pp_sha256() { sha256sum < "$1" | cut -c1-64; }

# --- receipts --------------------------------------------------------------------------------
# PP_OLD: the receipt the last install wrote, read once, as a sorted file of entries.
pp_load_receipt() {
  local r
  PP_OLD=$1
  r=$(pp_d "$INSTALL_RECEIPT")
  if [ -f "$r" ] && [ ! -L "$r" ]; then
    grep -v '^#' "$r" | LC_ALL=C sort -u > "$PP_OLD" || true
  else
    : > "$PP_OLD"
  fi
}

pp_have_receipt() {
  local r
  r=$(pp_d "$INSTALL_RECEIPT")
  [ -f "$r" ] && [ ! -L "$r" ]
}

# pp_in_old KIND VALUE PATH: is this exact entry in the old receipt?
pp_in_old() {
  grep -qxF "$1$PP_TAB$2$PP_TAB$3" "$PP_OLD"
}

pp_released() {
  printf '%s\n' "$PP_RELEASED" | grep -qxF "$2 $1"
}

# ours PATH [SOURCE] -> 0 if the regular file at PATH is one Pear put there.
pp_ours() {
  local r h
  r=$(pp_d "$1")
  [ -f "$r" ] && [ ! -L "$r" ] || return 1
  h=$(pp_sha256 "$r")
  if [ -n "${2:-}" ] && [ -f "$2" ] && [ "$h" = "$(pp_sha256 "$2")" ]; then
    return 0
  fi
  pp_in_old f "$h" "$1" && return 0
  pp_released "$1" "$h" && return 0
  return 1
}

# pp_link_ours PATH TARGET -> 0 if PATH is a symlink Pear put there.
pp_link_ours() {
  local r t
  r=$(pp_d "$1")
  [ -L "$r" ] || return 1
  t=$(readlink -- "$r")
  [ "$t" = "$2" ] && return 0
  pp_in_old l "$t" "$1"
}

# pp_manifest PATH...: the receipt entries describing what is on disk now at these system
# paths (files and symlinks, recursing into directories), sorted. A name sha256sum would have
# to escape (a backslash or a newline) is printed as an `x` entry, which matches nothing.
pp_manifest() {
  local p r
  for p in "$@"; do
    r=$(pp_d "$p")
    if [ -L "$r" ]; then
      printf 'l\t%s\t%s\n' "$(readlink -- "$r")" "$p"
    elif [ -d "$r" ]; then
      find "$r" -type l -printf 'l\t%l\t%p\n' | pp_strip_d
      find "$r" -type f -exec sha256sum -- {} + | pp_sumlines
    elif [ -f "$r" ]; then
      sha256sum -- "$r" | pp_sumlines
    fi
  done | LC_ALL=C sort -u
}

pp_strip_d() { awk -F "$PP_TAB" -v d="$PP_D" -v OFS="$PP_TAB" \
  '{ if (d != "" && index($3, d) == 1) $3 = substr($3, length(d) + 1); print }'; }

pp_sumlines() { awk -v d="$PP_D" '
  /^\\/ { print "x\t-\t" substr($0, 2); next }
  { p = substr($0, 67); if (d != "" && index(p, d) == 1) p = substr(p, length(d) + 1)
    print "f\t" substr($0, 1, 64) "\t" p }'; }

# --- the stage -------------------------------------------------------------------------------
# The stage is what install.sh copied out of the checkout. SHA256SUMS lists every file in it
# except wheels/*.whl (pip checks those against the hashes in backend/requirements.lock, which
# SHA256SUMS covers). The root command already checked SHA256SUMS against the published hash;
# this checks the rest again so install-root.sh never relies on its caller.
pp_stage_verify() {
  local s bad listed
  s=$1
  [ -f "$s/SHA256SUMS" ] && [ ! -L "$s/SHA256SUMS" ] || pp_die "the stage has no SHA256SUMS"
  (cd "$s" && sha256sum -c --strict --quiet SHA256SUMS) \
    || pp_die "the stage does not match its SHA256SUMS"
  bad=$(cd "$s" && find . -type l | head -n 5)
  [ -z "$bad" ] || pp_die "the stage contains symlinks: $(echo $bad)"
  bad=$(cd "$s" && find . ! -type d ! -type f | head -n 5)
  [ -z "$bad" ] || pp_die "the stage contains special files: $(echo $bad)"
  listed=$(cut -c67- "$s/SHA256SUMS")
  bad=$(cd "$s" && find . -type f ! -path ./SHA256SUMS | sed 's|^\./||' | LC_ALL=C sort \
        | while IFS= read -r f; do
            case $f in
              wheels/*/*) printf '%s\n' "$f" ;;
              wheels/*.whl) ;;
              *) printf '%s\n' "$listed" | grep -qxF -- "$f" || printf '%s\n' "$f" ;;
            esac
          done | head -n 5)
  [ -z "$bad" ] || pp_die "the stage contains files SHA256SUMS does not list: $(echo $bad)"
}

# --- the table -------------------------------------------------------------------------------
pp_row() { printf '%s\t%s\t%s\t%s\t%s\n' "$@"; }

# pp_table STAGE WORK: every thing the root step installs, one per line, tab-separated:
#   f DEST SRC MODE OWNER     a file (SRC is a real path in the stage or the work directory)
#   l DEST TARGET - -         a symlink
#   d DEST - MODE OWNER       a directory
# The venv is not in the table: it is built as a whole and recorded as a tree.
pp_table() {
  local s w f rel sub
  s=$1 w=$2
  pp_row d "$PREFIX" - 0755 root:root
  pp_row d "$APP_DIR" - 0755 root:root
  pp_row d "$LIBEXEC" - 0755 root:root
  pp_row d "${FONTS_CONF%/*}" - 0755 root:root
  pp_row d "$EMPTY_DIR" - 0555 root:root
  pp_row d "$INSTALL_STATE_DIR" - 0700 root:root

  # The window: every file under app/ in SHA256SUMS, except the two that go elsewhere.
  cut -c67- "$s/SHA256SUMS" | grep '^app/' | while IFS= read -r f; do
    rel=${f#app/}
    case $rel in
      fonts.conf|"$APP_ID.desktop") continue ;;
    esac
    sub=$rel
    while case $sub in */*) true ;; *) false ;; esac; do
      sub=${sub%/*}
      pp_row d "$APP_DIR/$sub" - 0755 root:root
    done
    pp_row f "$APP_DIR/$rel" "$s/$f" 0644 root:root
  done | LC_ALL=C sort -u
  # It draws with Omarchy's own components, so it follows the theme (root-owned, in /usr).
  pp_row l "$APP_DIR/Ui" "$PP_OMARCHY_SHELL/Ui" - -
  pp_row l "$APP_DIR/Commons" "$PP_OMARCHY_SHELL/Commons" - -

  pp_row f "$FONTS_CONF" "$s/app/fonts.conf" 0644 root:root
  pp_row f "$DESKTOP_FILE" "$s/app/$APP_ID.desktop" 0644 root:root
  pp_row f "$PEAR_EXEC" "$w/pear-exec" 2755 "root:$CLIENT_GROUP"
  pp_row f "$DAEMON_WRAPPER" "$s/system/libexec/pear-passwordsd" 0755 root:root
  pp_row f "$AUTOFILL_HOST" "$s/system/libexec/pear-autofill-host" 0755 root:root
  pp_row f "$UNINSTALL_ROOT" "$w/uninstall-root" 0755 root:root
  pp_row f "$PREFIX/VERSION" "$w/VERSION" 0644 root:root
  pp_row f "$AUTOFILL_REGISTER_BIN" "$s/system/bin/pear-passwords-autofill" 0755 root:root
  pp_row f "$UNIT_DIR/$SOCKET_UNIT" "$s/system/units/$SOCKET_UNIT" 0644 root:root
  pp_row f "$UNIT_DIR/$SERVICE_UNIT" "$s/system/units/$SERVICE_UNIT" 0644 root:root
  pp_row f "$UNIT_DIR/$SEAL_SOCKET_UNIT" "$s/system/units/$SEAL_SOCKET_UNIT" 0644 root:root
  pp_row f "$UNIT_DIR/$SEAL_SERVICE_UNIT" "$s/system/units/$SEAL_SERVICE_UNIT" 0644 root:root
  pp_row f "$SYSUSERS_CONF" "$s/system/sysusers.d/pear-passwords.conf" 0644 root:root
  pp_row f "$TMPFILES_CONF" "$s/system/tmpfiles.d/pear-passwords.conf" 0644 root:root
  pp_row f "$POLICY_FILE" "$s/polkit/$POLKIT_ACTION_PREFIX.policy" 0644 root:root
}

# Gate G1 fallback switch: the shipped daemon unit selects the root seal service with an
# active (uncommented) Environment=PEAR_SEAL_BACKEND=seal-service line.
pp_seal_service_selected() {
  grep -qx 'Environment=PEAR_SEAL_BACKEND=seal-service' "$1"
}

# Sources the table needs from the stage, for a clear error on a stage that is not 2.0.
pp_missing_sources() {
  local kind dest src mode own
  while IFS="$PP_TAB" read -r kind dest src mode own; do
    [ "$kind" = f ] || continue
    case $src in "$2"/*) continue ;; esac   # built or generated in the work directory
    [ -f "$src" ] || printf '%s\n' "${src#"$1"/}"
  done < "$3"
  return 0
}

# --- checks (all of them run before the first write) ----------------------------------------
# The same names anywhere that would override ours or be overridden by them, and drop-ins
# that would change the unit's hardening behind the receipt's back.
pp_shadows() {
  local u d r pol f
  for u in "$SOCKET_UNIT" "$SERVICE_UNIT" "$SEAL_SOCKET_UNIT" "$SEAL_SERVICE_UNIT"; do
    for d in /usr/lib/systemd/system /usr/local/lib/systemd/system /run/systemd/system \
             /etc/systemd/system.control /run/systemd/system.control /run/systemd/transient \
             /run/systemd/generator /run/systemd/generator.early /run/systemd/generator.late; do
      if pp_exists "$d/$u"; then
        printf '%s  (same name as a Pear unit; one would override the other)\n' "$d/$u"
      fi
    done
    for d in "$UNIT_DIR" /usr/lib/systemd/system /usr/local/lib/systemd/system \
             /run/systemd/system /etc/systemd/system.control /run/systemd/system.control; do
      if pp_exists "$d/$u.d"; then
        printf '%s  (a drop-in directory would change the unit)\n' "$d/$u.d"
      fi
    done
  done
  pol=${POLICY_FILE##*/}
  for d in /usr/local/share/polkit-1/actions /etc/polkit-1/actions; do
    if pp_exists "$d/$pol"; then
      printf '%s  (same name as the Pear policy)\n' "$d/$pol"
    fi
  done
  # Another policy file declaring one of our action ids would decide what "approve" means.
  for d in "${POLICY_FILE%/*}" /usr/local/share/polkit-1/actions /etc/polkit-1/actions; do
    r=$(pp_d "$d")
    [ -d "$r" ] || continue
    for f in "$r"/*.policy; do
      [ -f "$f" ] && [ "$f" != "$(pp_d "$POLICY_FILE")" ] || continue
      if grep -qF "id=\"$POLKIT_ACTION_PREFIX." "$f"; then
        printf '%s  (declares a Pear polkit action)\n' "${f#"$PP_D"}"
      fi
    done
  done
  return 0
}

pp_exists() { [ -e "$(pp_d "$1")" ] || [ -L "$(pp_d "$1")" ]; }

pp_check_identities() {
  local e uid home shell g members
  e=$(pp_getent passwd "$SERVICE_USER")
  if [ -n "$e" ]; then
    uid=$(printf '%s' "$e" | cut -d: -f3)
    home=$(printf '%s' "$e" | cut -d: -f6)
    shell=$(printf '%s' "$e" | cut -d: -f7)
    [ "$home" = "$STATE_DIR" ] \
      || printf 'user %s exists with home %s, not %s\n' "$SERVICE_USER" "$home" "$STATE_DIR"
    case $shell in
      */nologin|/bin/false|/usr/bin/false) ;;
      *) printf 'user %s exists with login shell %s\n' "$SERVICE_USER" "$shell" ;;
    esac
    [ "$uid" -lt "$MIN_CLIENT_UID" ] 2>/dev/null \
      || printf 'user %s exists as a regular account (uid %s)\n' "$SERVICE_USER" "$uid"
  fi
  g=$(pp_getent group "$CLIENT_GROUP")
  members=$(printf '%s' "$g" | cut -d: -f4)
  [ -z "$members" ] \
    || printf 'group %s has members (%s); it must have none\n' "$CLIENT_GROUP" "$members"
  return 0
}

# pp_check_all TABLE: print one line per problem, nothing if it is safe to install.
pp_check_all() {
  local t r kind dest src mode own value path
  t=$1
  if [ -e "$(pp_d "$PREFIX")" ] || [ -L "$(pp_d "$PREFIX")" ]; then
    pp_have_receipt || printf '%s  (exists, but there is no install receipt)\n' "$PREFIX"
  fi
  while IFS="$PP_TAB" read -r kind dest src mode own; do
    r=$(pp_d "$dest")
    pp_pp_new_problem "$kind" "$r" "$dest" "$src"
    [ -e "$r" ] || [ -L "$r" ] || continue
    case $kind in
      f)
        if [ -L "$r" ]; then
          printf '%s  (is a symlink)\n' "$dest"
        elif ! pp_ours "$dest" "$src"; then
          printf '%s  (exists and was not installed by Pear, or was edited)\n' "$dest"
        fi ;;
      l)
        pp_link_ours "$dest" "$src" \
          || printf '%s  (exists and is not the link Pear installs)\n' "$dest" ;;
      d)
        [ -d "$r" ] && [ ! -L "$r" ] || printf '%s  (is not a plain directory)\n' "$dest" ;;
    esac
  done < "$t"

  # Under $P: anything that is not a table entry must be exactly what the receipt recorded
  # (the venv, files a newer version no longer ships). Anything else was planted or edited.
  if [ -d "$(pp_d "$PREFIX")" ] && [ ! -L "$(pp_d "$PREFIX")" ]; then
    cut -f2 "$t" > "$t.dests"
    pp_manifest "$PREFIX" > "$t.cur"
    # <dest>.pp-new beside a table destination is checked by pp_pp_new_problem above.
    # $VENV.new/ and $VENV.old/ are names only this script uses inside root-only $P (a venv
    # being built, the previous venv during a swap): not hash-checked, deleted and rebuilt
    # once everything else is proven ours.
    awk -F "$PP_TAB" -v pre="$PREFIX" -v vnew="$VENV.new/" -v vold="$VENV.old/" '
      FILENAME == ARGV[1] { dest[$0] = 1; dest[$0 ".pp-new"] = 1; next }
      FILENAME == ARGV[2] { old[$0] = 1; next }
      index($3, vnew) == 1 || index($3, vold) == 1 || ($3 in dest) { next }
      !($0 in old) { print $3 "  (in " pre ", but not in the receipt, or edited since)" }
    ' "$t.dests" "$PP_OLD" "$t.cur"
    find "$(pp_d "$PREFIX")" ! -type d ! -type f ! -type l | pp_strip_plain \
      | sed 's/$/  (special file)/'
    rm -f "$t.dests" "$t.cur"
  fi

  # Receipt entries outside $P that this version no longer ships must still match, or
  # removing them later would delete someone's edit.
  while IFS="$PP_TAB" read -r kind value path; do
    case $kind in f|l) ;; *) continue ;; esac
    case $path in "$PREFIX"/*) continue ;; esac
    cut -f2 "$t" | grep -qxF -- "$path" && continue
    r=$(pp_d "$path")
    [ -e "$r" ] || [ -L "$r" ] || continue
    if [ "$kind" = f ]; then
      pp_ours "$path" || printf '%s  (no longer shipped, and edited since)\n' "$path"
    else
      pp_link_ours "$path" "$value" || printf '%s  (no longer shipped, and changed since)\n' "$path"
    fi
  done < "$PP_OLD"

  pp_shadows
  pp_check_identities
  return 0
}

# A file in a root-owned directory that root wrote. Test mode chowns nothing, so there every
# file is the test user's.
pp_root_owned() { [ "$PP_TEST" -eq 1 ] || [ "$(stat -c %u -- "$1")" = 0 ]; }

# <dest>.pp-new is the half-written copy an interrupted pp_install_row left beside a table
# destination (or, for a link row, the new link not yet renamed). It is accepted only when it
# is owned by root and is a byte prefix of the file Pear installs there (a link row: a link to
# that same target); pp_clean_pp_new then deletes it before anything is written. Anything
# else by that name is reported as in the way, like any other path.
pp_pp_new_problem() {
  local kind r dest src n
  kind=$1 r=$2.pp-new dest=$3 src=$4
  [ -e "$r" ] || [ -L "$r" ] || return 0
  if ! pp_root_owned "$r"; then
    printf '%s.pp-new  (left over, and not owned by root)\n' "$dest"
    return 0
  fi
  case $kind in
    f)
      if [ -L "$r" ] || [ ! -f "$r" ]; then
        printf '%s.pp-new  (left over, and not a plain file)\n' "$dest"
        return 0
      fi
      n=$(wc -c < "$r")
      if [ "$n" -gt "$(wc -c < "$src")" ] \
          || [ "$(sha256sum < "$r")" != "$(head -c "$n" -- "$src" | sha256sum)" ]; then
        printf '%s.pp-new  (left over, and not part of the file Pear installs there)\n' "$dest"
      fi ;;
    l)
      if [ ! -L "$r" ] || [ "$(readlink -- "$r")" != "$src" ]; then
        printf '%s.pp-new  (left over, and not the link Pear installs there)\n' "$dest"
      fi ;;
    *)
      printf '%s.pp-new  (in the way)\n' "$dest" ;;
  esac
}

# After the checks passed: every <dest>.pp-new left by an interrupted run goes, and so does
# the receipt's own half-written copy (pp_write_receipt writes it beside the receipt).
pp_clean_pp_new() {
  local kind dest src mode own r
  while IFS="$PP_TAB" read -r kind dest src mode own; do
    r=$(pp_d "$dest").pp-new
    if [ -L "$r" ] || [ -f "$r" ]; then rm -f -- "$r"; fi
  done < "$1"
  r=$(pp_d "$INSTALL_RECEIPT").pp-new
  if [ -L "$r" ] || [ -f "$r" ]; then rm -f -- "$r"; fi
  return 0
}

# Uninstall: the .pp-new leftovers beside every path the receipt records, and beside the
# receipt itself. Names only the installer writes, in root-owned directories; a file or a
# link owned by root, never a directory, never followed.
pp_remove_pp_new() {
  local kind value path r
  while IFS="$PP_TAB" read -r kind value path; do
    case $kind in f|l) ;; *) continue ;; esac
    r=$(pp_d "$path").pp-new
    if { [ -L "$r" ] || [ -f "$r" ]; } && pp_root_owned "$r"; then rm -f -- "$r"; fi
  done < "$1"
  r=$(pp_d "$INSTALL_RECEIPT").pp-new
  if { [ -L "$r" ] || [ -f "$r" ]; } && pp_root_owned "$r"; then rm -f -- "$r"; fi
  return 0
}

pp_strip_plain() { awk -v d="$PP_D" '{ if (d != "" && index($0, d) == 1) $0 = substr($0, length(d) + 1); print }'; }

# --- writing ---------------------------------------------------------------------------------
# Each file is written beside its destination and renamed over it, so a reader never sees a
# half-written unit, policy or binary.
pp_install_row() {
  local kind dest src mode own r
  kind=$1 dest=$2 src=$3 mode=$4 own=$5
  r=$(pp_d "$dest")
  case $kind in
    d)
      # shellcheck disable=SC2046
      install -d -m "$mode" $(pp_own "$own") "$r" ;;
    f)
      [ -d "${r%/*}" ] || install -d -m 0755 $(pp_own root:root) "${r%/*}"
      # shellcheck disable=SC2046
      install -m "$mode" $(pp_own "$own") "$src" "$r.pp-new"
      mv -fT "$r.pp-new" "$r" ;;
    l)
      [ -d "${r%/*}" ] || install -d -m 0755 $(pp_own root:root) "${r%/*}"
      rm -f "$r.pp-new"
      ln -s -- "$src" "$r.pp-new"
      mv -fT "$r.pp-new" "$r" ;;
  esac
}

pp_install_table() {
  local kind dest src mode own
  while IFS="$PP_TAB" read -r kind dest src mode own; do
    pp_install_row "$kind" "$dest" "$src" "$mode" "$own"
  done < "$1"
}

# pp_install_dest TABLE DEST: install just one row (the sysusers and tmpfiles files go first).
pp_install_dest() {
  local kind dest src mode own
  awk -F "$PP_TAB" -v d="$2" '$2 == d' "$1" | while IFS="$PP_TAB" read -r kind dest src mode own; do
    pp_install_row "$kind" "$dest" "$src" "$mode" "$own"
  done
}

# pp_new_receipt TABLE: the entries for what is on disk now, after installing.
pp_new_receipt() {
  local p
  {
    awk -F "$PP_TAB" -v OFS="$PP_TAB" '$1 == "d" { print "d", "-", $2 }' "$1"
    awk -F "$PP_TAB" '$1 != "d" { print $2 }' "$1" | while IFS= read -r p; do pp_manifest "$p"; done
    pp_manifest "$VENV"
  } | LC_ALL=C sort -u
}

# pp_planned_receipt TABLE: the old receipt plus every table entry, files recorded with the
# hash of their staged source. Written before the first write, so a run that is interrupted
# anywhere leaves a receipt that names everything it may have written: the next run then
# proves ownership from it instead of refusing a $P it cannot account for.
pp_planned_receipt() {
  {
    cat "$PP_OLD"
    awk -F "$PP_TAB" -v OFS="$PP_TAB" '$1 == "d" { print "d", "-", $2 } $1 == "l" { print "l", $3, $2 }' "$1"
    awk -F "$PP_TAB" -v OFS="$PP_TAB" '$1 == "f" { print $2, $3 }' "$1" \
      | while IFS="$PP_TAB" read -r dest src; do
          printf 'f\t%s\t%s\n' "$(pp_sha256 "$src")" "$dest"
        done
  } | LC_ALL=C sort -u
}

pp_write_receipt() {
  local r
  r=$(pp_d "$INSTALL_RECEIPT")
  # shellcheck disable=SC2046
  install -d -m 0700 $(pp_own root:root) "${r%/*}"
  { printf '%s\n' "$PP_RECEIPT_HEADER"; cat "$1"; } > "$r.pp-new"
  chmod 0600 "$r.pp-new"
  mv -fT "$r.pp-new" "$r"
}

# pp_remove_entries ENTRIES KEPT [TREE]: remove every file and symlink in ENTRIES that still
# matches exactly; append the ones that do not (edited, replaced) to KEPT. Then the empty
# directories of TREE (the venv, whose directories are not entries) are pruned, and the
# directories in ENTRIES are removed, deepest first, only if empty.
pp_remove_entries() {
  local kind value path r p
  {
    pp_manifest "$PREFIX"
    awk -F "$PP_TAB" -v p="$PREFIX/" '$1 != "d" && index($3, p) != 1 { print $3 }' "$1" \
      | while IFS= read -r p; do pp_manifest "$p"; done
  } > "$2.cur"
  # rm: still exactly as recorded. keep: something else is there now. check: not seen by the
  # manifest (gone, or now a directory or a special file); looked at one by one below.
  awk -F "$PP_TAB" '
    FILENAME == ARGV[1] { cur[$0] = 1; at[$3] = 1; next }
    $1 != "f" && $1 != "l" { next }
    ($0 in cur) { print "rm\t" $3; next }
    ($3 in at) { print "keep\t" $0; next }
    { print "check\t" $0 }
  ' "$2.cur" "$1" > "$2.plan"
  awk -F "$PP_TAB" -v d="$PP_D" '$1 == "rm" { print d $2 }' "$2.plan" \
    | xargs -r -d '\n' rm -f --
  awk -F "$PP_TAB" -v OFS="$PP_TAB" '$1 == "keep" { print $2, $3, $4 }' "$2.plan" >> "$2"
  awk -F "$PP_TAB" -v OFS="$PP_TAB" '$1 == "check" { print $2, $3, $4 }' "$2.plan" \
    | while IFS="$PP_TAB" read -r kind value path; do
        r=$(pp_d "$path")
        if [ -e "$r" ] || [ -L "$r" ]; then
          printf '%s\t%s\t%s\n' "$kind" "$value" "$path" >> "$2"
        fi
      done
  rm -f "$2.cur" "$2.plan"
  [ -z "${3:-}" ] || pp_prune_empty_dirs "$3"
  awk -F "$PP_TAB" '$1 == "d" { print length($3) "\t" $3 }' "$1" | LC_ALL=C sort -rn \
    | cut -f2 | while IFS= read -r p; do
        rmdir -- "$(pp_d "$p")" 2>/dev/null || true
      done
  return 0
}

# Directories inside the venv are not receipt entries; remove the empty ones it leaves.
pp_prune_empty_dirs() {
  local r
  r=$(pp_d "$1")
  [ -d "$r" ] && [ ! -L "$r" ] || return 0
  find "$r" -type d -empty -delete 2>/dev/null || true
}

# The 1.x action, only when it is byte-for-byte one that 1.x handed out.
pp_remove_legacy_policy() {
  local r
  r=$(pp_d "$LEGACY_POLICY_FILE")
  [ -e "$r" ] || [ -L "$r" ] || return 0
  if [ ! -L "$r" ] && [ -f "$r" ] && pp_released "$LEGACY_POLICY_FILE" "$(pp_sha256 "$r")"; then
    rm -f -- "$r"
    pp_say "Removed the 1.x polkit action $LEGACY_POLICY_FILE"
  else
    pp_warn "kept $LEGACY_POLICY_FILE: it is not a copy Pear 1.x installed"
  fi
}
