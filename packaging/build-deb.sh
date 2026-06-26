#!/usr/bin/env bash
# Build the packetsonde Debian package.
#
# Enforces that debian/changelog's top version matches PS_VERSION_STR in the
# root CMakeLists.txt -- the package version and the binary's reported version
# must always agree so a host's `packetsonde version` confirms which .deb it
# took (same verifiable-swap policy as the dev-push patch bump).
#
# Host build-deps: debhelper devscripts dpkg-dev  (plus the Build-Depends in
# debian/control, installed via `sudo apt build-dep .` or bootstrap-ubuntu.sh).
set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$REPO_ROOT"

# PS_VERSION_STR from the single source of truth.
CMAKE_VER="$(sed -n 's/^[[:space:]]*set(PS_VERSION_STR "\([0-9.]*\)").*/\1/p' CMakeLists.txt | head -1)"
# Top changelog version, e.g. "packetsonde (0.1.4) unstable; ..."
CHANGELOG_VER="$(sed -n 's/^packetsonde (\([0-9.]*\)).*/\1/p' debian/changelog | head -1)"

if [ -z "$CMAKE_VER" ]; then
    echo "ERROR: could not read PS_VERSION_STR from CMakeLists.txt" >&2
    exit 1
fi
if [ "$CMAKE_VER" != "$CHANGELOG_VER" ]; then
    echo "ERROR: version mismatch." >&2
    echo "  CMakeLists.txt PS_VERSION_STR = $CMAKE_VER" >&2
    echo "  debian/changelog top version  = $CHANGELOG_VER" >&2
    echo "Sync them before building, e.g.:" >&2
    echo "  dch -v $CMAKE_VER -D unstable 'Build $CMAKE_VER'" >&2
    exit 1
fi

echo "=== Building packetsonde $CMAKE_VER (.deb) ==="
dpkg-buildpackage -us -uc -b

DEB="$(ls -1t "$REPO_ROOT"/../packetsonde_"${CMAKE_VER}"_*.deb 2>/dev/null | head -1)"
echo ""
echo "=== Build complete ==="
if [ -n "$DEB" ]; then
    echo "Package: $DEB"
    echo "Install: sudo apt install \"$DEB\""
else
    echo "Package written to the parent directory ($REPO_ROOT/..)."
fi
