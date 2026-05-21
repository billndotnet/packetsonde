#!/bin/bash
# Bootstrap a Debian/Ubuntu host with the packages packetsonde needs.
# Run BEFORE ./build.sh. Idempotent: re-runs are safe.
#
# Covers Ubuntu 22.04 LTS, 24.04 LTS, and Debian 12. Older Debian
# releases may need to fall back to the OpenSSL 1.1 packages.
set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "This script needs root. Re-run with: sudo $0"
    exit 1
fi

echo "=== packetsonde bootstrap (Debian/Ubuntu) ==="
echo

# Detect distro release for diagnostics; not used to gate package names.
if [ -r /etc/os-release ]; then
    . /etc/os-release
    echo "Distro: ${NAME:-unknown} ${VERSION:-}"
fi
echo

PACKAGES=(
    # Build toolchain
    build-essential        # gcc, g++, make, libc6-dev
    cmake
    pkg-config
    git

    # Required runtime + build libraries
    libssl-dev             # OpenSSL: TLS audit, mTLS, Ed25519
    libedit-dev            # psctl REPL
    libpcap-dev            # agent passive capture
    libhiredis-dev         # agent Redis bridge (optional but default ON)

    # Test dependencies
    python3                # integration tests use Python mocks
    python3-cryptography   # discovery test signs Ed25519 in Python
    netcat-openbsd         # readiness checks in some tests

    # Operational nice-to-haves
    jq                     # the README's quickstart pipe target
)

echo "Updating apt index ..."
apt-get update -qq

echo "Installing ${#PACKAGES[@]} packages ..."
DEBIAN_FRONTEND=noninteractive apt-get install -y "${PACKAGES[@]}"

echo
echo "=== Bootstrap complete ==="
echo "Next: ./build.sh"
