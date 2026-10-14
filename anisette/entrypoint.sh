#!/bin/sh
# Gate Apple's libraries on the recorded digests before the server can load them.
#
# Upstream source/app.d fetches applemusic.apk from Apple's CDN whenever the two
# libraries are missing, extracts them and loads them. It checks nothing. So
# recording their digests in apple-libs.sha256 bought detection after the fact
# and nothing else: the bytes that got loaded were whatever the CDN served.
#
# This runs in their place. The libraries are fetched here, checked against the
# digests baked into the image, and only then written where the server looks -
# so by the time the server starts, its own download path has nothing to do.
# A mismatch stops the server rather than being reported alongside a running one.
set -eu

DIGESTS=/opt/apple-libs.sha256
LIBDIR=/home/Alcoholic/.config/anisette-v3/lib
APK_URL=https://apps.mzstatic.com/content/android-apple-music-apk/applemusic.apk

# The digests are for the x86_64 members of the APK, and both base images are
# pinned to linux/amd64, so this should be unreachable. It is here because the
# failure it prevents is loading a different architecture's libraries unchecked.
if [ "$(uname -m)" != "x86_64" ]; then
    echo "anisette: refusing to start on $(uname -m): apple-libs.sha256 records x86_64 digests" >&2
    exit 1
fi

# --adi-path moves the directory the server loads libraries from, which would
# leave this gate checking a directory nothing reads.
for arg in "$@"; do
    case "$arg" in
        -a|--adi-path|--adi-path=*)
            echo "anisette: refusing $arg: it moves the library directory this gate checks" >&2
            exit 1
            ;;
    esac
done

check() {
    # sha256sum -c wants only its own lines; the file is mostly explanation.
    ( cd "$1" && grep -v '^[[:space:]]*#' "$DIGESTS" | grep . | sha256sum -c --quiet )
}

mkdir -p "$LIBDIR"

if [ ! -f "$LIBDIR/libCoreADI.so" ] || [ ! -f "$LIBDIR/libstoreservicescore.so" ]; then
    echo "anisette: fetching Apple's libraries from $APK_URL"
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    curl -fsSL "$APK_URL" -o "$tmp/applemusic.apk"
    unzip -p "$tmp/applemusic.apk" lib/x86_64/libCoreADI.so > "$tmp/libCoreADI.so"
    unzip -p "$tmp/applemusic.apk" lib/x86_64/libstoreservicescore.so > "$tmp/libstoreservicescore.so"
    # Checked in the temporary directory: nothing reaches LIBDIR unless it matches.
    if ! check "$tmp"; then
        echo "anisette: REFUSING TO START" >&2
        echo "  Apple's libraries do not match the digests in anisette/apple-libs.sha256." >&2
        echo "  Nothing was installed. The likeliest cause by far is a new Apple Music" >&2
        echo "  release at that URL, which is not itself evidence of anything wrong - but" >&2
        echo "  these are not the bytes that were reviewed, so a person decides." >&2
        echo "  docs/anisette-provenance.md says how to re-record them." >&2
        exit 1
    fi
    mv "$tmp/libCoreADI.so" "$tmp/libstoreservicescore.so" "$LIBDIR/"
    rm -rf "$tmp"
    trap - EXIT
fi

# Libraries already in the volume get checked too. That an earlier start wrote
# them is not evidence: the volume outlives the image and is writable.
if ! check "$LIBDIR"; then
    echo "anisette: REFUSING TO START" >&2
    echo "  the libraries in $LIBDIR do not match anisette/apple-libs.sha256." >&2
    echo "  docs/anisette-provenance.md says how to re-record them." >&2
    exit 1
fi

exec /opt/anisette-v3-server "$@"
