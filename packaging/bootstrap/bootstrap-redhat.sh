#!/bin/bash
# Bootstrap a RHEL-family host (RHEL, Fedora, AlmaLinux, Rocky, CentOS
# Stream, Amazon Linux 2023). Run BEFORE ./build.sh. Idempotent.
#
# Requires the EPEL repo on RHEL/Alma/Rocky for hiredis-devel.
set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "This script needs root. Re-run with: sudo $0"
    exit 1
fi

echo "=== packetsonde bootstrap (RHEL family) ==="
echo

if [ -r /etc/os-release ]; then
    . /etc/os-release
    echo "Distro: ${NAME:-unknown} ${VERSION:-}"
fi
echo

# Prefer dnf if present; fall back to yum.
PM=dnf
command -v dnf >/dev/null 2>&1 || PM=yum

# EPEL provides hiredis-devel on RHEL/Alma/Rocky. Fedora has it in base.
case "${ID:-}" in
    rhel|almalinux|rocky|centos)
        echo "Enabling EPEL ..."
        $PM install -y epel-release || \
            echo "warn: epel-release install failed -- hiredis may not be available"
        ;;
esac

PACKAGES=(
    # Build toolchain
    gcc
    gcc-c++
    make
    cmake
    pkgconfig
    git

    # Required libraries
    openssl-devel
    libedit-devel
    libpcap-devel
    hiredis-devel

    # Test dependencies
    python3
    python3-cryptography
    nmap-ncat              # provides `nc` on RHEL family

    # Nice-to-haves
    jq
)

echo "Installing ${#PACKAGES[@]} packages with $PM ..."
$PM install -y "${PACKAGES[@]}"

echo
echo "=== Bootstrap complete ==="
echo "Next: ./build.sh"
