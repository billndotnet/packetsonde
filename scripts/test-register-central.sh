#!/bin/bash
# Integration: register a throwaway agent against a live central, verify a
# pending ps_agents doc appears. Clean up the doc afterward on the central side.
#
# Usage: scripts/test-register-central.sh [central-url]
#   default central-url: http://127.0.0.1:8700  (loopback; use the host LAN IP
#   from a machine that can reach it)
set -e
CENTRAL="${1:-http://127.0.0.1:8700}"
BIN="${PACKETSONDE_BIN:-./build/src/cli/packetsonde}"
AID="test-agent-$(openssl rand -hex 6)"
TMP=$(mktemp -d)
mkdir -p "$TMP/keys"
cat > "$TMP/packetsonded.toml" <<EOF
[keys]
dir = "$TMP/keys"
[central]
url = "$CENTRAL"
agent_id = "$AID"
deployment_mode = "host"
verify = "0"
EOF

echo "registering $AID against $CENTRAL ..."
"$BIN" register --config "$TMP/packetsonded.toml" --provenance direct
echo
echo "Now verify on central: GET /api/v1/packetsonde/agents?status=pending should list:"
echo "  agent_id = $AID"
echo "(validate it, then a checkin should show it online; remember to delete the test doc)"
rm -rf "$TMP"
