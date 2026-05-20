#!/bin/bash
# Build the example audit-vnc plugin against an installed packetsonde build.
# Adjust PACKETSONDE_SRC and PACKETSONDE_BUILD to where you cloned + built.
set -e

PACKETSONDE_SRC="${PACKETSONDE_SRC:-/Users/billn/packetsonde}"
PACKETSONDE_BUILD="${PACKETSONDE_BUILD:-$PACKETSONDE_SRC/build}"

uname_s=$(uname -s)
case "$uname_s" in
    Darwin) ext=dylib; cflags="-undefined dynamic_lookup" ;;
    Linux)  ext=so;    cflags="" ;;
    *) echo "unsupported platform: $uname_s"; exit 1 ;;
esac

clang -shared -fPIC -O2 -DPS_AUDIT_PLUGIN_BUILD=1 \
    -I "$PACKETSONDE_SRC/src/lib" \
    -L "$PACKETSONDE_BUILD/src/lib" -lpacketsonde_lib \
    $cflags \
    -o "audit-vnc.$ext" audit-vnc.c

echo "built: audit-vnc.$ext"
echo "install with:"
echo "  mkdir -p ~/.config/packetsonde/audits"
echo "  cp audit-vnc.$ext ~/.config/packetsonde/audits/"
echo "then: packetsonde audit vnc <host[:port]>"
