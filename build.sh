#!/bin/bash
# Build packetsonde -- agent + CLI.
#   ./build.sh           build agent + cli (default)
#   ./build.sh agent     agent only
#   ./build.sh cli       cli only
#   ./build.sh native    agent + cli (alias)
#
# Portable: works on macOS, Linux, anything with a POSIX shell + cmake.

set -e
trap 'echo ""; echo "=== BUILD FAILED ==="' ERR

# Resolve the repo root from the script's own location so the build
# works no matter what directory the user invokes us from.
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
BUILD_DIR="${PS_BUILD_DIR:-$PROJECT_DIR/build}"

# Portable CPU count: GNU nproc on Linux, sysctl on macOS, getconf
# everywhere else, fall back to 1.
ncpu() {
    if   command -v nproc   >/dev/null 2>&1; then nproc
    elif command -v sysctl  >/dev/null 2>&1 && sysctl -n hw.ncpu >/dev/null 2>&1; then
        sysctl -n hw.ncpu
    elif command -v getconf >/dev/null 2>&1; then
        getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1
    else
        echo 1
    fi
}

TARGET="${1:-native}"

echo "=== packetsonde build ($TARGET) ==="
echo "    Project: $PROJECT_DIR"
echo "    Build:   $BUILD_DIR"
echo "    Branch:  $(cd "$PROJECT_DIR" && git branch --show-current 2>/dev/null || echo none)"
echo "    HEAD:    $(cd "$PROJECT_DIR" && git log --oneline -1 2>/dev/null || echo none)"
echo "    Jobs:    $(ncpu)"
echo ""

build_native() {
    local goal="$1"   # all|agent|cli
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"
    cmake "$PROJECT_DIR" 2>&1 | tail -8
    case "$goal" in
        agent) cmake --build . -j "$(ncpu)" --target packetsonde-agent --target packetsonde-priv 2>&1 | tail -20 ;;
        cli)   cmake --build . -j "$(ncpu)" --target packetsonde                                  2>&1 | tail -20 ;;
        all)   cmake --build . -j "$(ncpu)"                                                       2>&1 | tail -20 ;;
    esac
}

case "$TARGET" in
    agent)         echo "--- Agent ---";   build_native agent ;;
    cli)           echo "--- CLI ---";     build_native cli ;;
    native|all)    echo "--- Native ---";  build_native all ;;
    *)
        echo "Unknown target: $TARGET"
        echo "Usage: $0 [agent|cli|native]"
        exit 2
        ;;
esac

echo ""
echo "=== Build complete ==="
echo "    Binaries in: $BUILD_DIR/src/{cli,agent}/"
