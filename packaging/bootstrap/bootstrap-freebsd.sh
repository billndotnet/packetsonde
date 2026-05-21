#!/bin/sh
# Bootstrap a FreeBSD / OPNsense / pfSense host. Run BEFORE ./build.sh.
# Idempotent.
#
# libedit and libpcap ship in base. OpenSSL in base is LibreSSL on
# OPNsense -- the build uses whatever cmake's find_package picks first.
# If the base SSL doesn't satisfy you, pass OPENSSL_ROOT_DIR to build.sh.
#
# Note: this script uses /bin/sh, not bash. Once installed, ./build.sh
# requires bash from pkg.
set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "This script needs root. Re-run with: sudo $0"
    exit 1
fi

echo "=== packetsonde bootstrap (FreeBSD / OPNsense) ==="
echo

if [ -r /etc/os-release ]; then
    . /etc/os-release
    echo "Distro: ${NAME:-unknown} ${VERSION:-}"
elif command -v uname >/dev/null 2>&1; then
    echo "Distro: $(uname -sr)"
fi
echo

# OPNsense restricts pkg by default. Operators sometimes set
# REPO_AUTOUPDATE=NO in /usr/local/etc/pkg.conf. If pkg refuses to
# update, fall back to building on a sibling FreeBSD VM and scp'ing
# the binaries -- see docs/build.md.
if ! pkg update -f; then
    echo
    echo "warn: 'pkg update' failed. On OPNsense you may need to enable"
    echo "      the FreeBSD package repository or build on a sibling VM."
    echo "      See docs/build.md for the cross-build approach."
    exit 1
fi

PACKAGES="
    bash
    cmake
    pkgconf
    git
    openssl
    hiredis
    python3
    py311-cryptography
    jq
"

echo "Installing packages ..."
# shellcheck disable=SC2086
pkg install -y $PACKAGES || {
    echo
    echo "warn: some packages failed. py311-cryptography in particular may"
    echo "      need a different python version suffix on your FreeBSD"
    echo "      release -- try: pkg search 'py3.-cryptography'"
    exit 1
}

echo
echo "=== Bootstrap complete ==="
echo "Next: ./build.sh"
echo
echo "Note: ./build.sh requires bash; it's installed to /usr/local/bin/bash."
echo "      The script uses /usr/bin/env bash so this should just work."
