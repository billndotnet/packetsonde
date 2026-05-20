#!/bin/bash
# Build packetsonde — agent + CLI.
#   ./build.sh           build agent + cli (default)
#   ./build.sh agent     agent only
#   ./build.sh cli       cli only
#   ./build.sh native    agent + cli (alias)

set -e
trap 'echo ""; echo "=== BUILD FAILED ==="' ERR

PROJECT_DIR="/Users/billn/packetsonde"
BUILD_DIR="$PROJECT_DIR/build"

TARGET="${1:-native}"

echo "=== packetsonde build ($TARGET) ==="
echo "    Branch: $(cd "$PROJECT_DIR" && git branch --show-current 2>/dev/null || echo none)"
echo "    HEAD:   $(cd "$PROJECT_DIR" && git log --oneline -1 2>/dev/null || echo none)"
echo ""

build_native() {
    local goal="$1"   # all|agent|cli
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"
    cmake "$PROJECT_DIR" 2>&1 | tail -5
    case "$goal" in
        agent) make -j"$(sysctl -n hw.ncpu)" packetsonde-agent packetsonde-priv 2>&1 | tail -20 ;;
        cli)   make -j"$(sysctl -n hw.ncpu)" packetsonde                          2>&1 | tail -20 ;;
        all)   make -j"$(sysctl -n hw.ncpu)"                                       2>&1 | tail -20 ;;
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
