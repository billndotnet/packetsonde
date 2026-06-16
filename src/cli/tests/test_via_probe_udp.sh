#!/usr/bin/env bash
# End-to-end test: bring up the agent's network_listener in-process via a tiny
# test driver, run `packetsonde --via testagent probe udp 127.0.0.1:PORT`
# against a trivial python UDP echo server, assert a probe finding frame came
# back with a via_agent field set.
#
# Privilege-free correctness proof for remote UDP probe dispatch: CLI
# `probe --via` -> agent type:"probe" dispatch -> `probe udp` runs -> finding
# frames stream back. The echo server guarantees an application-layer reply,
# so the probe classifies the target as open without any raw socket.
set -e

BUILD_DIR="${PS_BUILD_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/build}"
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

# Trivial UDP echo server -- probe target. Echoes the first datagram back to
# the sender, then exits.
UDP_PORT=$((30000 + RANDOM % 20000))
UDP_FIFO=$(mktemp -u); mkfifo "$UDP_FIFO"
python3 - "$UDP_PORT" "$UDP_FIFO" <<'PY' &
import socket, sys
port = int(sys.argv[1]); fifo = sys.argv[2]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
with open(fifo, "w") as f: f.write("ready\n")
data, addr = s.recvfrom(2048)
s.sendto(data if data else b"\x00", addr)
s.close()
PY
UDP_PID=$!
trap "kill $UDP_PID 2>/dev/null || true; rm -f $UDP_FIFO; rm -rf $KDIR $AGENTS_CFG" EXIT
read UDP_READY < "$UDP_FIFO"

# Spin up the agent listener via the test driver. Redirect its output to a log
# rather than inheriting our stdout (see test_via_probe_tcp.sh for the held-
# pipe rationale under ctest).
LISTEN_PORT=$((30000 + RANDOM % 20000))
PS_KEY_DIR="$KDIR" \
PS_AGENT_LISTEN_ENABLED=1 \
PS_AGENT_LISTEN_PORT="$LISTEN_PORT" \
PS_AGENT_LISTEN_KEY="agent" \
PS_AGENT_AUTHORIZED_DIR="$ADIR" \
PS_PACKETSONDE_BIN="$CLI" \
"$DRIVER" >"$KDIR/driver.log" 2>&1 &
DRIVER_PID=$!
reap() {
    kill "$DRIVER_PID" 2>/dev/null || true
    kill "$UDP_PID"    2>/dev/null || true
    for _ in 1 2 3; do kill -0 "$DRIVER_PID" 2>/dev/null || break; sleep 0.2; done
    kill -9 "$DRIVER_PID" 2>/dev/null || true
    rm -f "$UDP_FIFO"; rm -rf "$KDIR" "$AGENTS_CFG"
}
trap reap EXIT

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
      "$CLI" --jsonl --via testagent probe udp "127.0.0.1:$UDP_PORT" 2>/dev/null || true)

fail() { echo "FAIL: $1"; echo "OUTPUT:"; echo "$OUT"; exit 1; }
echo "$OUT" | grep -q '"kind":"probe.udp.open"'  || fail "missing probe.udp.open finding"
echo "$OUT" | grep -q '"via_agent":"testagent"'  || fail "missing via_agent"

echo "test_via_probe_udp: OK"
