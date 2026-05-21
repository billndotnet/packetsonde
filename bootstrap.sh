#!/bin/sh
# packetsonde build-dep bootstrap dispatcher.
#
# Detects the platform and runs the right per-distro script under
# packaging/bootstrap/. Always run BEFORE ./build.sh on a fresh host.
#
# To force a specific platform (e.g., when /etc/os-release lies on a
# derivative distro):
#
#   PS_BOOTSTRAP_AS=ubuntu  ./bootstrap.sh
#   PS_BOOTSTRAP_AS=redhat  ./bootstrap.sh
#   PS_BOOTSTRAP_AS=freebsd ./bootstrap.sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
BOOTSTRAP_DIR="$SCRIPT_DIR/packaging/bootstrap"

# Explicit override wins.
case "${PS_BOOTSTRAP_AS:-}" in
    ubuntu|debian) exec sudo "$BOOTSTRAP_DIR/bootstrap-ubuntu.sh" ;;
    redhat|rhel|fedora|alma|rocky|centos)
                   exec sudo "$BOOTSTRAP_DIR/bootstrap-redhat.sh" ;;
    freebsd|opnsense|pfsense)
                   exec sudo "$BOOTSTRAP_DIR/bootstrap-freebsd.sh" ;;
esac

# Otherwise: detect from /etc/os-release on Linux, or uname on BSD.
OS_ID=""
OS_LIKE=""
if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-}"
    OS_LIKE="${ID_LIKE:-}"
elif [ "$(uname -s)" = "FreeBSD" ]; then
    OS_ID="freebsd"
elif [ "$(uname -s)" = "Darwin" ]; then
    OS_ID="darwin"
fi

case "$OS_ID" in
    ubuntu|debian|linuxmint|pop|raspbian)
        echo "Detected ${OS_ID} -- running bootstrap-ubuntu.sh"
        exec sudo "$BOOTSTRAP_DIR/bootstrap-ubuntu.sh"
        ;;
    rhel|fedora|almalinux|rocky|centos|amzn)
        echo "Detected ${OS_ID} -- running bootstrap-redhat.sh"
        exec sudo "$BOOTSTRAP_DIR/bootstrap-redhat.sh"
        ;;
    freebsd|opnsense|pfsense|hbsd)
        echo "Detected ${OS_ID} -- running bootstrap-freebsd.sh"
        exec sudo "$BOOTSTRAP_DIR/bootstrap-freebsd.sh"
        ;;
    darwin)
        echo "Detected macOS. Use Homebrew directly:"
        echo "  brew install cmake openssl@3 libpcap hiredis pkg-config"
        echo "Then: ./build.sh"
        exit 0
        ;;
esac

# Fall back to ID_LIKE for derivative distros.
case "$OS_LIKE" in
    *debian*|*ubuntu*)
        echo "Detected debian-like ($OS_LIKE) -- running bootstrap-ubuntu.sh"
        exec sudo "$BOOTSTRAP_DIR/bootstrap-ubuntu.sh"
        ;;
    *rhel*|*fedora*)
        echo "Detected RHEL-like ($OS_LIKE) -- running bootstrap-redhat.sh"
        exec sudo "$BOOTSTRAP_DIR/bootstrap-redhat.sh"
        ;;
esac

echo "Unrecognized platform (ID=$OS_ID, ID_LIKE=$OS_LIKE)."
echo "Force a profile with:  PS_BOOTSTRAP_AS={ubuntu|redhat|freebsd} ./bootstrap.sh"
exit 1
