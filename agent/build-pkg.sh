#!/bin/sh
# Build a FreeBSD package for packetsonde-agent.
#
# Usage: ./build-pkg.sh [--output dist/]
# Must be run on FreeBSD.

set -e

OUTPUT="dist"
while [ $# -gt 0 ]; do
    case "$1" in
        --output) OUTPUT="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--output dist/]"
            echo "Must be run on FreeBSD."
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [ "$(uname -s)" != "FreeBSD" ]; then
    echo "Error: must be run on FreeBSD" >&2
    exit 1
fi

NPROC=$(sysctl -n hw.ncpu)

echo "Building packetsonde-agent..."

mkdir -p build && cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local -DSYSCONFDIR=/usr/local/etc
make -j"$NPROC"

STAGEDIR=$(mktemp -d)
make DESTDIR="$STAGEDIR" install

rm -f "$STAGEDIR/usr/local/lib/systemd/system/packetsonde-agent.service"

cd ..
mkdir -p "$OUTPUT"

VERSION=$(grep 'project(' CMakeLists.txt | sed 's/.*VERSION \([0-9.]*\).*/\1/')
cat > "$STAGEDIR/+MANIFEST" <<MANIFEST
name: packetsonde-agent
version: "$VERSION"
origin: net/packetsonde-agent
comment: "Passive network sensor with honeypot and flow generation"
maintainer: "bill@billn.net"
www: "https://github.com/billndotnet/Netrunner"
prefix: /usr/local
desc: "PacketSonde network agent for bridge sensor deployment"
MANIFEST

pkg create -m "$STAGEDIR" -r "$STAGEDIR" -o "$OUTPUT/" 2>/dev/null || echo "Note: pkg create requires FreeBSD pkg tools"
rm -rf "$STAGEDIR"

echo ""
echo "Built:"
ls -la "$OUTPUT"/packetsonde-agent-*.pkg 2>/dev/null || echo "Package in $OUTPUT/"
