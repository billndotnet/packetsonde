#!/usr/bin/env bash
# End-to-end test: bring up the agent's network_listener in-process via
# a tiny test driver, run `packetsonde --via testagent probe tcp
# 127.0.0.1:PORT` against a trivial python TCP listener, assert a probe
# finding frame came back with a via_agent field set.
#
# This is the privilege-free correctness proof for remote probe dispatch:
# CLI `probe --via` -> agent type:"probe" dispatch -> `probe tcp` runs
# -> finding frames stream back. `probe tcp` is connect-based, so no raw
# sockets are required.
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

# Trivial TCP listener -- probe target. Accepts one connection and sends a
# banner, then closes.
TCP_PORT=$((30000 + RANDOM % 20000))
TCP_FIFO=$(mktemp -u); mkfifo "$TCP_FIFO"
python3 - "$TCP_PORT" "$TCP_FIFO" <<'PY' &
import socket, sys
port = int(sys.argv[1])
fifo = sys.argv[2]
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port)); s.listen(1)
with open(fifo, "w") as f: f.write("ready\n")
c, _ = s.accept()
c.send(b"PROBE-BANNER hello\r\n")
c.close(); s.close()
PY
TCP_PID=$!
trap "kill $TCP_PID 2>/dev/null || true; rm -f $TCP_FIFO; rm -rf $KDIR $AGENTS_CFG" EXIT
read TCP_READY < "$TCP_FIFO"

# Spin up the agent listener via the test driver. Redirect its output to a
# log rather than inheriting our stdout: the driver forks a packetsonde
# subprocess per inbound --via connection, and that child keeps the inherited
# stdout open. Under ctest (which reads the test's stdout to EOF) that held
# pipe blocks the run until timeout even after the script has finished and
# reaped the driver. The sibling via tests already redirect for this reason.
LISTEN_PORT=$((30000 + RANDOM % 20000))
PS_KEY_DIR="$KDIR" \
PS_AGENT_LISTEN_ENABLED=1 \
PS_AGENT_LISTEN_PORT="$LISTEN_PORT" \
PS_AGENT_LISTEN_KEY="agent" \
PS_AGENT_AUTHORIZED_DIR="$ADIR" \
PS_PACKETSONDE_BIN="$CLI" \
"$DRIVER" >"$KDIR/driver.log" 2>&1 &
DRIVER_PID=$!
# Reap the driver on exit. SIGTERM alone is unreliable here: the listener's
# accept thread is blocked in accept() and its shutdown path can stall, so
# the process may not exit on SIGTERM and would linger holding the listen
# port (wedging later runs). Send SIGTERM, then SIGKILL as a backstop.
reap() {
    kill "$DRIVER_PID" 2>/dev/null || true
    kill "$TCP_PID"    2>/dev/null || true
    for _ in 1 2 3; do kill -0 "$DRIVER_PID" 2>/dev/null || break; sleep 0.2; done
    kill -9 "$DRIVER_PID" 2>/dev/null || true
    rm -f "$TCP_FIFO"; rm -rf "$KDIR" "$AGENTS_CFG"
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
      "$CLI" --jsonl --via testagent probe tcp "127.0.0.1:$TCP_PORT" 2>/dev/null || true)

fail() { echo "FAIL: $1"; echo "OUTPUT:"; echo "$OUT"; exit 1; }
echo "$OUT" | grep -q '"kind":"probe.tcp.open"' || fail "missing probe.tcp.open finding"
echo "$OUT" | grep -q '"via_agent":"testagent"' || fail "missing via_agent"

echo "test_via_probe_tcp: OK"
