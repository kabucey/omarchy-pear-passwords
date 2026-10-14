#!/bin/sh
# Print the 12-hex-digit id of what Pear changes in the upstream anisette build: the sha256 of
# the sha256sum lines of apple-root-ca.pem and patches/*.patch, in that order. It is part of the
# image tag, so systemd/pear-passwords-anisette.service names it too (a test keeps them equal).
set -eu
cd "$(dirname "$0")"
sha256sum apple-root-ca.pem patches/*.patch | sha256sum | cut -c1-12
