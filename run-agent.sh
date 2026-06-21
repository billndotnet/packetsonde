#!/bin/sh
# Start the packetsonde agent on macOS with the IPC socket the UE client expects.
# Run with sudo (pcap needs root):  sudo ./run-agent.sh
set -e

SOCK="${PS_AGENT_SOCKET:-/tmp/packetsonde-agent.sock}"
IFACE="${PS_CAPTURE_INTERFACE:-en0}"

# Clear any stale socket from a prior run so bind() succeeds.
rm -f "$SOCK"

echo "packetsonde agent: iface=$IFACE socket=$SOCK"
exec env PS_CAPTURE_INTERFACE="$IFACE" PS_AGENT_SOCKET="$SOCK" \
    ./build/src/agent/packetsonded -vv
