#!/usr/bin/env bash
# Look at the Apple libraries in the live anisette volume from the host, and
# compare them with the digests in anisette/apple-libs.sha256.
#
# This is for looking, not for enforcing. The enforcement is anisette/entrypoint.sh
# inside the container, which checks the same file before the server starts and
# refuses to start it on a mismatch - a check the operator has to remember to run
# is not a check. This script exists because inspecting a volume without starting
# anything is sometimes what you want.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VOL="${ANISETTE_VOLUME:-icp-anisette}"

libdir="$(podman volume inspect "$VOL" --format '{{.Mountpoint}}' 2>/dev/null)/lib" || {
    echo "anisette: no podman volume '$VOL'; nothing to check yet" >&2
    exit 1
}

status=0
while read -r want name; do
    [[ -z "${want:-}" || "$want" == \#* ]] && continue
    f="$libdir/$name"
    if [[ ! -f "$f" ]]; then
        echo "MISSING  $name (not downloaded yet)"
        status=1
        continue
    fi
    got="$(podman unshare sha256sum "$f" | cut -d' ' -f1)"
    if [[ "$got" == "$want" ]]; then
        echo "OK       $name"
    else
        echo "CHANGED  $name"
        echo "         recorded $want"
        echo "         on disk  $got"
        status=1
    fi
done < "$HERE/apple-libs.sha256"

exit "$status"
