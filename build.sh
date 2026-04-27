#!/bin/bash
# Build packetsonde — agent + UE editor module.
#   ./build.sh         build both
#   ./build.sh agent   agent only
#   ./build.sh editor  editor only

set -e
trap 'echo ""; echo "=== BUILD FAILED ==="' ERR

PROJECT_DIR="/Users/billn/packetsonde"
PROJECT_FILE="$PROJECT_DIR/packetsonde.uproject"
UE_DIR="/Users/Shared/Epic Games/UE_5.7"
BUILD_SCRIPT="$UE_DIR/Engine/Build/BatchFiles/Mac/Build.sh"

AGENT_DIR="$PROJECT_DIR/agent"
AGENT_BUILD="$AGENT_DIR/build"

TARGET="${1:-all}"

echo "=== packetsonde build ($TARGET) ==="
echo "    Branch: $(cd "$PROJECT_DIR" && git branch --show-current 2>/dev/null || echo none)"
echo "    HEAD:   $(cd "$PROJECT_DIR" && git log --oneline -1 2>/dev/null || echo none)"
echo ""

if [ "$TARGET" = "all" ] || [ "$TARGET" = "agent" ]; then
    echo "--- Agent ---"
    mkdir -p "$AGENT_BUILD"
    cd "$AGENT_BUILD"
    cmake .. 2>&1 | tail -3
    make -j"$(sysctl -n hw.ncpu)" 2>&1 | tail -20
    echo ""
fi

if [ "$TARGET" = "all" ] || [ "$TARGET" = "editor" ]; then
    echo "--- Editor ---"
    cd "$PROJECT_DIR"
    "$BUILD_SCRIPT" packetsondeEditor Mac Development "$PROJECT_FILE" 2>&1 | tail -15
    echo ""
fi

echo "=== Build complete ==="
