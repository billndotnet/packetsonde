#!/bin/sh
# Build a Debian package for packetsonde-agent.
#
# Usage: ./build-deb.sh [--arch arm64] [--output dist/]
#
# Requires: dpkg-buildpackage, debhelper, cmake, libpcap-dev, libhiredis-dev, libssl-dev

set -e

ARCH=""
OUTPUT="dist"

while [ $# -gt 0 ]; do
    case "$1" in
        --arch)   ARCH="$2"; shift 2 ;;
        --output) OUTPUT="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--arch arm64] [--output dist/]"
            echo ""
            echo "Options:"
            echo "  --arch ARCH   Cross-build for architecture (e.g. arm64)"
            echo "  --output DIR  Output directory for .deb (default: dist/)"
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if ! command -v dpkg-buildpackage >/dev/null 2>&1; then
    echo "Error: dpkg-buildpackage not found. Install dpkg-dev." >&2
    exit 1
fi

DPKG_ARGS="-us -uc -b"
if [ -n "$ARCH" ]; then
    DPKG_ARGS="$DPKG_ARGS -a $ARCH"
    echo "Cross-building for $ARCH"
fi

echo "Building .deb package..."
dpkg-buildpackage $DPKG_ARGS

mkdir -p "$OUTPUT"
mv ../packetsonde-agent_*.deb "$OUTPUT/" 2>/dev/null || true
mv ../packetsonde-agent_*.buildinfo "$OUTPUT/" 2>/dev/null || true
mv ../packetsonde-agent_*.changes "$OUTPUT/" 2>/dev/null || true

echo ""
echo "Built:"
ls -la "$OUTPUT"/packetsonde-agent_*.deb 2>/dev/null || echo "No .deb found — check build output above"
