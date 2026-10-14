#!/usr/bin/env bash
# Build the anisette server from pinned upstream source.
#
# Usage: anisette/build.sh [commit-sha]
#
# With no argument it builds the revision pinned in Containerfile, which is the
# one systemd/pear-passwords-anisette.service runs. Takes a couple of minutes:
# it compiles the server from D source. See docs/anisette-provenance.md.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# The Containerfile holds the pinned revision; nothing here keeps a second copy
# of it that could drift.
REV="${1:-$(sed -n 's/^ARG ANISETTE_REV=\([0-9a-f]\{40\}\)$/\1/p' "$HERE/Containerfile")}"
if [[ ! "$REV" =~ ^[0-9a-f]{40}$ ]]; then
    echo "anisette: refusing to build from '$REV': need a full 40-character commit SHA" >&2
    exit 1
fi

# The patches Pear applies (patches/, and the CA the patched code trusts) change the image
# without changing the upstream revision, so their hash is part of the tag and a label.
# install.sh computes the same value with patch-id.sh.
PATCHES="$("$HERE/patch-id.sh")"
IMAGE="localhost/pear-passwords-anisette:$REV-$PATCHES"

echo "anisette: building $IMAGE from Dadoum/anisette-v3-server@$REV with patches $PATCHES"
podman build --build-arg "ANISETTE_REV=$REV" --build-arg "PEAR_PATCHES=$PATCHES" \
    -t "$IMAGE" -f "$HERE/Containerfile" "$HERE"

# The image has to be able to say what it was built from, or it is no better
# than the unlabelled upstream one.
got="$(podman image inspect --format '{{index .Labels "org.opencontainers.image.revision"}}' "$IMAGE")"
got_patches="$(podman image inspect --format '{{index .Labels "io.github.dragosol.pear-passwords.patches"}}' "$IMAGE")"
if [[ "$got_patches" != "$PATCHES" ]]; then
    echo "anisette: built image claims patches '$got_patches', expected '$PATCHES'" >&2
    exit 1
fi
if [[ "$got" != "$REV" ]]; then
    echo "anisette: built image claims revision '$got', expected '$REV'" >&2
    exit 1
fi

echo
echo "anisette: built $IMAGE"
echo "  revision: $got"
echo "  image id: $(podman image inspect --format '{{.Id}}' "$IMAGE")"
echo
echo "The image id is specific to this build: apt and the D package registry are"
echo "resolved at build time, so two machines building the same commit do not get"
echo "byte-identical images. The revision label, not the id, is what is pinned."
