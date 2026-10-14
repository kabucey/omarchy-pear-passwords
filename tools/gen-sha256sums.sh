#!/bin/sh
# Regenerate SHA256SUMS, and the pinned hash of it in README.md's root command.
#
#   tools/gen-sha256sums.sh           rewrite both
#   tools/gen-sha256sums.sh --check   change nothing; exit 1 if either is out of date
#
# SHA256SUMS lists every file install.sh stages for the root step: manifest.json and
# everything git tracks (or would track) under app/, backend/ (except backend/tests/),
# native/, polkit/ and system/. Wheels are not listed; pip checks them against the hashes in
# backend/requirements.lock, which is. The sha256 of SHA256SUMS itself is what the release
# notes publish and what the root command checks first.
#
# Run it after any change under those paths, commit both files, and put the printed hash in
# the release notes. backend/tests/test_sha256sums_current.py fails until you do.
set -eu
LC_ALL=C
export LC_ALL

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
check=0
[ "${1:-}" = --check ] && check=1

die() { printf 'gen-sha256sums: %s\n' "$*" >&2; exit 1; }

files() {
  git ls-files -co --exclude-standard -- manifest.json app backend native polkit system \
    | grep -v '^backend/tests/' | sort -u | while IFS= read -r f; do
        [ -f "$f" ] && [ ! -L "$f" ] || continue   # deleted in the work tree, or a symlink
        printf '%s\n' "$f"
      done
}

git rev-parse --is-inside-work-tree >/dev/null 2>&1 || die "run this from a git checkout"
bad=$(files | grep -n '[[:space:]\\]' || true)
[ -z "$bad" ] || die "file names with whitespace or a backslash cannot be staged: $bad"
links=$(git ls-files -co --exclude-standard -- app backend native polkit system \
        | while IFS= read -r f; do [ -L "$f" ] && printf '%s ' "$f"; done || true)
[ -z "$links" ] || die "symlinks cannot be staged (the root step refuses them): $links"

new=$(files | while IFS= read -r f; do sha256sum -- "$f"; done)
hash=$(printf '%s\n' "$new" | sha256sum | cut -c1-64)
pattern='echo "[0-9a-f]\{64\}  SHA256SUMS"'
grep -q "$pattern" README.md || die "README.md has no root command with a pinned hash"

if [ "$check" -eq 1 ]; then
  ok=0
  if [ "$(cat SHA256SUMS 2>/dev/null)" != "$new" ]; then
    echo "SHA256SUMS is out of date:" >&2
    printf '%s\n' "$new" | diff SHA256SUMS - >&2 || true
    ok=1
  fi
  if ! grep -q "echo \"$hash  SHA256SUMS\"" README.md; then
    echo "README.md does not pin $hash" >&2
    ok=1
  fi
  [ "$ok" -eq 0 ] && echo "SHA256SUMS and README.md are current ($hash)"
  exit "$ok"
fi

printf '%s\n' "$new" > SHA256SUMS
sed -i "s/$pattern/echo \"$hash  SHA256SUMS\"/" README.md
echo "SHA256SUMS: $(printf '%s\n' "$new" | wc -l) files"
echo "sha256 of SHA256SUMS (publish this in the release notes): $hash"
