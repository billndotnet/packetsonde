#!/bin/bash
# Fully central-free collector round-trip on loopback. The edge reports in relay mode
# straight to the collector, which verifies against its local authorized/ set and writes
# JSONL. The edge connects via mTLS with its 'default' key but signs envelopes with its
# 'agent' key, so BOTH edge pubkeys go in the collector's authorized/. No central.
set -u
cd "$(dirname "$0")/.."
BIN=./build/src/cli/packetsonde
PORT="${PORT:-18490}"
TMP=$(mktemp -d); CK="$TMP/ck"; EK="$TMP/ek"
mkdir -p "$CK/authorized" "$EK/keys"

# Identities.
PS_KEY_DIR="$CK"      "$BIN" key generate --name agent   >/dev/null 2>&1 || true   # collector identity
PS_KEY_DIR="$EK/keys" "$BIN" key generate --name default >/dev/null 2>&1 || true   # edge mTLS client
PS_KEY_DIR="$EK/keys" "$BIN" key generate --name agent   >/dev/null 2>&1 || true   # edge envelope signer

# Authorize both edge pubkeys at the collector.
cp "$EK/keys/default.pub" "$CK/authorized/edge-default.pub"
cp "$EK/keys/agent.pub"   "$CK/authorized/edge-agent.pub"

# Collector fingerprint -> the edge's agent registry (so relay_via=collector resolves).
CFPR=$(PS_KEY_DIR="$CK" "$BIN" key fingerprint agent 2>/dev/null | tr -d '[:space:]')
printf '[agents.collector]\naddress = "127.0.0.1:%s"\nkey_fingerprint = "%s"\nknock = false\n' \
    "$PORT" "$CFPR" > "$TMP/agents.toml"
printf '[keys]\ndir = "%s/keys"\n[central]\nurl = "http://127.0.0.1:1"\nagent_id = "edge-07"\nreport_mode = "relay"\nrelay_via = "collector"\nverify = "0"\n' \
    "$EK" > "$TMP/edge.toml"

# Start the collector (background), give it a moment to bind.
PS_KEY_DIR="$CK" "$BIN" collect --key-dir "$CK" --authorized "$CK/authorized" \
    --listen "127.0.0.1:$PORT" --out "$TMP/collected.jsonl" >"$TMP/collect.log" 2>&1 &
CPID=$!
sleep 1

printf '{"v":1,"id":"01C","run_id":"01R","ts":"%s","source":"audit.tls","host":"h","kind":"tls.weak_cipher","severity":"medium","confidence":"firm","title":"t"}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$TMP/f.jsonl"
echo "=== edge report ==="
PS_AGENTS_TOML="$TMP/agents.toml" PS_KEY_DIR="$EK/keys" "$BIN" report-central \
    --to-central "$TMP/f.jsonl" --config "$TMP/edge.toml" 2>&1 | tail -2
sleep 1
kill "$CPID" 2>/dev/null || true

echo "=== collected.jsonl ==="; cat "$TMP/collected.jsonl" 2>/dev/null
# edge->collector is DIRECT (the edge is the origin, no relay hop) -> transport "direct".
if grep -q '"verified":true' "$TMP/collected.jsonl" 2>/dev/null && \
   grep -q '"agent_id":"edge-07"' "$TMP/collected.jsonl" 2>/dev/null; then
    echo "PASS: verified finding collected, no central"
    RC=0
else
    echo "FAIL: expected a verified finding in collected.jsonl"
    RC=1
fi
rm -rf "$TMP"
exit $RC
