#!/usr/bin/env bash
# Multi-hop --via e2e: CLI -> bunker -> trunkbox -> audit target.
#
# Spins up two agent instances on loopback (with different listen ports +
# their own agents.toml each) and runs:
#   packetsonde --via bunker --via trunkbox audit ssh <mock>
#
# The request travels bunker -> trunkbox, the audit subprocess runs on
# trunkbox against the mock, findings stream back through both hops.
set -e
trap 'echo; echo "=== test_via_multihop FAILED (line $LINENO) ==="' ERR

BUILD_DIR="${PS_BUILD_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/build}"
CLI="$BUILD_DIR/src/cli/packetsonde"
DRIVER="$BUILD_DIR/src/agent/test_network_listener_driver"

if [ ! -x "$CLI" ] || [ ! -x "$DRIVER" ]; then
    echo "skip: $CLI or $DRIVER not built"; exit 77
fi
if ! command -v python3 >/dev/null 2>&1; then echo "skip: no python3"; exit 77; fi

WORK=$(mktemp -d -t ps-multihop.XXXXXX)
cleanup() {
    [ -n "${BUNKER_PID:-}" ]   && kill $BUNKER_PID   2>/dev/null || true
    [ -n "${TRUNKBOX_PID:-}" ] && kill $TRUNKBOX_PID 2>/dev/null || true
    [ -n "${SSH_PID:-}" ]      && kill $SSH_PID      2>/dev/null || true
    # Escalate to SIGKILL so a wedged driver never orphans (matches the
    # reap pattern in test_via_e2e / test_via_probe_tcp).
    for pid in "${BUNKER_PID:-}" "${TRUNKBOX_PID:-}"; do
        [ -n "$pid" ] || continue
        for _ in 1 2 3; do kill -0 "$pid" 2>/dev/null || break; sleep 0.2; done
        kill -9 "$pid" 2>/dev/null || true
    done
    rm -rf "$WORK"
}
trap cleanup EXIT

CLI_KEYS="$WORK/cli-keys"
BUNKER_KEYS="$WORK/bunker-keys"
TRUNKBOX_KEYS="$WORK/trunkbox-keys"
mkdir -p "$CLI_KEYS" "$BUNKER_KEYS/authorized" "$TRUNKBOX_KEYS/authorized"

# Generate keys.
PS_KEY_DIR="$CLI_KEYS"      "$CLI" key generate --name default >/dev/null
PS_KEY_DIR="$BUNKER_KEYS"   "$CLI" key generate --name agent   >/dev/null
PS_KEY_DIR="$BUNKER_KEYS"   "$CLI" key generate --name client  >/dev/null  # bunker's CLI key when it forwards
PS_KEY_DIR="$TRUNKBOX_KEYS" "$CLI" key generate --name agent   >/dev/null

# Trust relationships:
#   bunker  authorizes cli/default.pub (so the CLI can connect to bunker)
#   trunkbox authorizes bunker/client.pub (so bunker can connect to trunkbox)
cp "$CLI_KEYS/default.pub"    "$BUNKER_KEYS/authorized/cli.pub"
cp "$BUNKER_KEYS/client.pub"  "$TRUNKBOX_KEYS/authorized/bunker.pub"

CLI_FPR=$(PS_KEY_DIR="$CLI_KEYS"      "$CLI" key fingerprint default | sed 's/^sha256://')
BUNKER_FPR=$(PS_KEY_DIR="$BUNKER_KEYS" "$CLI" key fingerprint agent  | sed 's/^sha256://')
TRUNKBOX_FPR=$(PS_KEY_DIR="$TRUNKBOX_KEYS" "$CLI" key fingerprint agent | sed 's/^sha256://')

# Mock SSH target. One accept per request; multi-hop only opens one
# back-end connection.
SSH_PORT=$((30000 + RANDOM % 20000))
SSH_FIFO="$WORK/ssh-ready"; mkfifo "$SSH_FIFO"
python3 - "$SSH_PORT" "$SSH_FIFO" <<'PY' &
import socket, sys
port = int(sys.argv[1]); fifo = sys.argv[2]
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port)); s.listen(2)
open(fifo, "w").write("ready\n")
for _ in range(2):
    c, _ = s.accept()
    c.send(b"SSH-2.0-OpenSSH_6.0p1\r\n")
    c.close()
s.close()
PY
SSH_PID=$!
read READY < "$SSH_FIFO"

# trunkbox: terminus. Runs the audit subprocess. Its agents.toml is
# empty -- trunkbox has nothing to forward to.
TRUNKBOX_PORT=$((30000 + RANDOM % 20000))
TRUNKBOX_AGENTS="$WORK/trunkbox-agents.toml"
: > "$TRUNKBOX_AGENTS"
PS_AGENT_LISTEN_MODE=persistent \
PS_AGENT_LISTEN_PORT=$TRUNKBOX_PORT \
PS_AGENT_LISTEN_KEY=agent \
PS_AGENT_AUTHORIZED_DIR="$TRUNKBOX_KEYS/authorized" \
PS_KEY_DIR="$TRUNKBOX_KEYS" \
PS_PACKETSONDE_BIN="$CLI" \
PS_AGENTS_TOML="$TRUNKBOX_AGENTS" \
"$DRIVER" >"$WORK/trunkbox.log" 2>&1 &
TRUNKBOX_PID=$!

# bunker: forwarder. Its agents.toml has a 'trunkbox' entry pinning
# trunkbox's pubkey, address points at trunkbox's listener.
BUNKER_PORT=$((30000 + RANDOM % 20000))
BUNKER_AGENTS="$WORK/bunker-agents.toml"
cat > "$BUNKER_AGENTS" <<EOF
[agents.trunkbox]
address = "127.0.0.1:$TRUNKBOX_PORT"
key_fingerprint = "sha256:$TRUNKBOX_FPR"
EOF
# bunker's CLI key (the one IT presents when forwarding to trunkbox)
# must be the 'default' key in its PS_KEY_DIR -- audit_via.c looks for
# 'default' specifically.
mv "$BUNKER_KEYS/client.pub" "$BUNKER_KEYS/default.pub"
mv "$BUNKER_KEYS/client.sec" "$BUNKER_KEYS/default.sec"

PS_AGENT_LISTEN_MODE=persistent \
PS_AGENT_LISTEN_PORT=$BUNKER_PORT \
PS_AGENT_LISTEN_KEY=agent \
PS_AGENT_AUTHORIZED_DIR="$BUNKER_KEYS/authorized" \
PS_KEY_DIR="$BUNKER_KEYS" \
PS_PACKETSONDE_BIN="$CLI" \
PS_AGENTS_TOML="$BUNKER_AGENTS" \
"$DRIVER" >"$WORK/bunker.log" 2>&1 &
BUNKER_PID=$!

# Wait for both listeners.
for port in $TRUNKBOX_PORT $BUNKER_PORT; do
    for i in $(seq 1 50); do
        if nc -z 127.0.0.1 "$port" 2>/dev/null; then break; fi
        sleep 0.1
    done
done

# CLI side: agents.toml entry for bunker only; trunkbox is reached
# only via bunker's own registry.
CLI_AGENTS="$WORK/cli-agents.toml"
cat > "$CLI_AGENTS" <<EOF
[agents.bunker]
address = "127.0.0.1:$BUNKER_PORT"
key_fingerprint = "sha256:$BUNKER_FPR"
EOF

OUT=$(PS_AGENTS_TOML="$CLI_AGENTS" PS_KEY_DIR="$CLI_KEYS" \
      "$CLI" --jsonl --via bunker --via trunkbox \
      audit ssh "127.0.0.1:$SSH_PORT" 2>/dev/null || true)

fail() { echo "FAIL: $1"; echo "OUTPUT:"; echo "$OUT"; echo
                            echo "bunker.log:"; sed 's/^/  /' "$WORK/bunker.log"
                            echo "trunkbox.log:"; sed 's/^/  /' "$WORK/trunkbox.log"
                            exit 1; }
echo "$OUT" | grep -q '"kind":"ssh.metadata"'    || fail "missing ssh.metadata"
echo "$OUT" | grep -q '"kind":"ssh.old_version"' || fail "missing ssh.old_version"
# Multi-hop via_agent is an array, innermost-first: trunkbox spliced the
# original finding, then bunker re-spliced as it forwarded back to the CLI.
echo "$OUT" | grep -q '"via_agent":\["trunkbox","bunker"\]' \
    || fail "missing via_agent chain"

echo "test_via_multihop: OK"
