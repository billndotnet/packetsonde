#!/bin/bash
# End-to-end test: bring up the agent's network_listener in-process via
# a tiny test driver, run `packetsonde --via testagent audit ssh
# 127.0.0.1:MOCK` against it, assert finding frames came back with a
# via_agent field set.
set -e

BUILD_DIR="${PS_BUILD_DIR:-/Users/billn/packetsonde/build}"
CLI="$BUILD_DIR/src/cli/packetsonde"
DRIVER="$BUILD_DIR/src/agent/test_network_listener_driver"

if [ ! -x "$CLI" ] || [ ! -x "$DRIVER" ]; then
    echo "skip: $CLI or $DRIVER not built"
    exit 77
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "skip: no python3"
    exit 77
fi

KDIR=$(mktemp -d)
ADIR="$KDIR/authorized"
mkdir "$ADIR"
AGENTS_CFG=$(mktemp)
trap "rm -rf $KDIR $AGENTS_CFG" EXIT

# Generate CLI key + agent key.
PS_KEY_DIR="$KDIR" "$CLI" key generate --name default >/dev/null
PS_KEY_DIR="$KDIR" "$CLI" key generate --name agent   >/dev/null
# Authorize the CLI's pubkey on the agent side.
cp "$KDIR/default.pub" "$ADIR/cli.pub"

CLI_FPR=$(PS_KEY_DIR="$KDIR" "$CLI" key fingerprint default | sed 's/^sha256://')
AGENT_FPR=$(PS_KEY_DIR="$KDIR" "$CLI" key fingerprint agent | sed 's/^sha256://')

# Mock SSH server -- audit target.
SSH_PORT=$((30000 + RANDOM % 20000))
SSH_FIFO=$(mktemp -u); mkfifo "$SSH_FIFO"
python3 - "$SSH_PORT" "$SSH_FIFO" <<'PY' &
import socket, sys
port = int(sys.argv[1])
fifo = sys.argv[2]
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port)); s.listen(1)
with open(fifo, "w") as f: f.write("ready\n")
c, _ = s.accept()
c.send(b"SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2\r\n")
c.close(); s.close()
PY
SSH_PID=$!
trap "kill $SSH_PID 2>/dev/null || true; rm -f $SSH_FIFO; rm -rf $KDIR $AGENTS_CFG" EXIT
read SSH_READY < "$SSH_FIFO"

# Spin up the agent listener via the test driver.
LISTEN_PORT=$((30000 + RANDOM % 20000))
PS_KEY_DIR="$KDIR" \
PS_AGENT_LISTEN_ENABLED=1 \
PS_AGENT_LISTEN_PORT="$LISTEN_PORT" \
PS_AGENT_LISTEN_KEY="agent" \
PS_AGENT_AUTHORIZED_DIR="$ADIR" \
PS_PACKETSONDE_BIN="$CLI" \
"$DRIVER" &
DRIVER_PID=$!
trap "kill $DRIVER_PID 2>/dev/null || true; kill $SSH_PID 2>/dev/null || true; rm -f $SSH_FIFO; rm -rf $KDIR $AGENTS_CFG" EXIT

# Wait for listener to bind.
for i in $(seq 1 30); do
    if nc -z 127.0.0.1 "$LISTEN_PORT" 2>/dev/null; then break; fi
    sleep 0.1
done

# Write an agents.toml that points at our listener with the agent's
# fingerprint pinned.
cat > "$AGENTS_CFG" <<EOF
[agents.testagent]
address = "127.0.0.1:$LISTEN_PORT"
key_fingerprint = "sha256:$AGENT_FPR"
EOF

OUT=$(XDG_CONFIG_HOME="$KDIR-cfg" \
      PS_AGENTS_TOML="$AGENTS_CFG" \
      PS_KEY_DIR="$KDIR" \
      "$CLI" --jsonl --via testagent audit ssh "127.0.0.1:$SSH_PORT" 2>/dev/null || true)

fail() { echo "FAIL: $1"; echo "OUTPUT:"; echo "$OUT"; exit 1; }
echo "$OUT" | grep -q '"kind":"ssh.metadata"'   || fail "missing ssh.metadata"
echo "$OUT" | grep -q '"kind":"ssh.old_version"' || fail "missing ssh.old_version"
echo "$OUT" | grep -q '"via_agent":"testagent"'  || fail "missing via_agent"

echo "test_via_e2e: OK"
