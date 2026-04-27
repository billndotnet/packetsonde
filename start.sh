#!/bin/bash
# Stop any running packetsonde processes, then launch agent + UE editor.
# Run with sudo if the agent needs raw-socket / setuid privileges.

set -e

PROJECT_DIR="/Users/billn/packetsonde"
PROJECT_FILE="$PROJECT_DIR/packetsonde.uproject"
UE_DIR="/Users/Shared/Epic Games/UE_5.7"
EDITOR_BIN="$UE_DIR/Engine/Binaries/Mac/UnrealEditor.app/Contents/MacOS/UnrealEditor"

AGENT_BIN="$PROJECT_DIR/agent/build/packetsonde-agent"

IS_ROOT=0
REAL_USER="$(whoami)"
if [ "$(id -u)" -eq 0 ]; then
    IS_ROOT=1
    REAL_USER="${SUDO_USER:-root}"
fi

echo "=== packetsonde start (root=$IS_ROOT, user=$REAL_USER) ==="

echo "--- Stopping any running instances ---"
pkill -9 -x "packetsonde-agent" 2>/dev/null && echo "    Killed packetsonde-agent" || echo "    packetsonde-agent not running"
pkill -x "UnrealEditor" 2>/dev/null && echo "    Killed UnrealEditor" || echo "    UnrealEditor not running"
sleep 1
rm -f /tmp/packetsonde-agent.sock

echo ""
echo "--- Launching agent ---"
if [ ! -x "$AGENT_BIN" ]; then
    echo "    Agent binary not found at $AGENT_BIN — run ./build.sh agent first."
    exit 1
fi

if [ $IS_ROOT -eq 1 ]; then
    sudo -u "$REAL_USER" "$AGENT_BIN" -c /dev/null &
else
    "$AGENT_BIN" -c /dev/null &
fi
AGENT_PID=$!
sleep 1
if kill -0 "$AGENT_PID" 2>/dev/null; then
    echo "    Agent running (pid $AGENT_PID)"
else
    echo "    WARNING: agent did not stay up"
fi

echo ""
echo "--- Launching editor ---"
if [ $IS_ROOT -eq 1 ]; then
    sudo -u "$REAL_USER" "$EDITOR_BIN" "$PROJECT_FILE" -nocrashreporter &
else
    "$EDITOR_BIN" "$PROJECT_FILE" -nocrashreporter &
fi

echo ""
echo "=== packetsonde running ==="
echo "    Agent:  pid $AGENT_PID"
echo "    Socket: /tmp/packetsonde-agent.sock"
echo "    Stop:   pkill packetsonde-agent && pkill UnrealEditor"
