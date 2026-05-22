#!/bin/bash
# Two-agent relay round-trip against psdev (loopback). ASSISTED: the relay needs a
# running packetsonded with agent_listen (root/caps), so this script does the parts
# it can (register + validate both agents, write configs) and prints the host steps
# + the assertions to check. UUID-scoped ids; clean up after.
set -e
cd "$(dirname "$0")/.."
PY=/opt/psdev-0522-3/venv/bin/python
EXP="PYTHONPATH=/opt/repo/rna/rna BASE_CONFIG=/opt/etc/psdev/config.yml"
EDGE="edge-$(openssl rand -hex 3)"; RELAY="relay-$(openssl rand -hex 3)"
TMP=$(mktemp -d); mkdir -p "$TMP/edge-keys" "$TMP/relay-keys"

for who in "$EDGE:$TMP/edge-keys" "$RELAY:$TMP/relay-keys"; do
  id="${who%%:*}"; kd="${who##*:}"
  cat > "$TMP/$id.toml" <<EOF
[keys]
dir = "$kd"
[central]
url = "http://127.0.0.1:8700"
agent_id = "$id"
verify = "0"
EOF
  ./build/src/cli/packetsonde register --config "$TMP/$id.toml" --provenance direct >/dev/null
  env $EXP $PY -c "from backend.framework.es import get_es_client; get_es_client().update(index='psdev_ps_agents', id='$id', doc={'status':'validated'}, refresh='wait_for')"
  echo "registered + validated $id (keys: $kd)"
done

# Relay fingerprint the edge must be allowed to relay through:
RELAY_FPR=$(./build/src/cli/packetsonde key fingerprint --dir "$TMP/relay-keys" --name agent 2>/dev/null || echo '<run: packetsonde key fingerprint>')
EDGE_FPR=$(./build/src/cli/packetsonde key fingerprint --dir "$TMP/edge-keys" --name agent 2>/dev/null || echo '<edge fingerprint>')

cat <<EOF

=== HOST STEPS (need root/caps for the relay's agent_listen) ===
1. Start the relay daemon (as root) with agent_listen + relay role:
     PS_KEY_DIR=$TMP/relay-keys \\
     PS_AGENT_LISTEN_MODE=persistent PS_AGENT_LISTEN_ADDR=127.0.0.1 PS_AGENT_LISTEN_PORT=8442 \\
     PS_AGENT_AUTHORIZED_DIR=$TMP/relay-keys/authorized \\
     PS_CENTRAL_URL=http://127.0.0.1:8700 PS_CENTRAL_AGENT_ID=$RELAY PS_CENTRAL_VERIFY=0 \\
     PS_RELAY_ROLE=1 PS_RELAY_ALLOW_SOURCES=$EDGE_FPR \\
     ./build/src/agent/packetsonded
   (authorize the edge: copy the edge agent pubkey into $TMP/relay-keys/authorized/)
2. Register the relay in the CLI agent registry (so the edge can resolve relay_via=$RELAY):
     add an entry for '$RELAY' (address 127.0.0.1:8442, key_fingerprint $RELAY_FPR) to agents.toml
3. Point the edge config at the relay + report:
     append to $TMP/$EDGE.toml:  report_mode = "relay"   relay_via = "$RELAY"
     printf '{"v":1,"id":"01R","run_id":"01R","ts":"2026-05-22T19:00:00Z","source":"audit.tls","host":"h","kind":"tls.weak_cipher","severity":"medium","confidence":"firm","title":"t"}\n' > $TMP/f.jsonl
     ./build/src/cli/packetsonde report-central --to-central $TMP/f.jsonl --config $TMP/$EDGE.toml

=== VERIFY (psdev) ===
  - psdev_ps_events has the $EDGE event: transport=relay, relay_path[0].verified=true,
    relay_chain_verified=true, relay_path[0].relay_agent_id=$RELAY
  - psdev_ps_relay_edges has ($EDGE -> $RELAY) state=verified

=== CLEANUP ===
  env $EXP $PY -c "from backend.framework.es import get_es_client as g; es=g(); \\
    [es.options(ignore_status=[404]).delete(index='psdev_ps_agents', id=i) for i in ('$EDGE','$RELAY')]"
  (also delete the $EDGE/$RELAY docs from psdev_ps_events + psdev_ps_relay_edges)
  rm -rf $TMP
EOF
