#!/bin/bash
# Regression: --fail-on works for findings forwarded over --via.
#
# Previously, audit_via.c's emit_finding_passthrough wrote directly to
# stdout, bypassing ps_output's severity counters. That meant --fail-on
# never tripped for via-routed runs even though the findings were
# present on the wire. This test runs an ssh audit through a local
# agent against a mock that announces an old OpenSSH (medium severity)
# and asserts the CLI exits 3 with --fail-on severity>=medium.
set -e

BUILD_DIR="${PS_BUILD_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/build}"
CLI="$BUILD_DIR/src/cli/packetsonde"
DRIVER="$BUILD_DIR/src/agent/test_network_listener_driver"

if [ ! -x "$CLI" ] || [ ! -x "$DRIVER" ]; then
    echo "skip: $CLI or $DRIVER not built"; exit 77
fi
if ! command -v python3 >/dev/null 2>&1; then echo "skip: no python3"; exit 77; fi

WORK=$(mktemp -d -t ps-via-fail-on.XXXXXX)
KDIR="$WORK/keys"; ADIR="$KDIR/authorized"
AGENTS_CFG="$WORK/agents.toml"
mkdir -p "$ADIR"

PS_KEY_DIR="$KDIR" "$CLI" key generate --name default >/dev/null
PS_KEY_DIR="$KDIR" "$CLI" key generate --name agent   >/dev/null
cp "$KDIR/default.pub" "$ADIR/cli.pub"
AGENT_FPR=$(PS_KEY_DIR="$KDIR" "$CLI" key fingerprint agent | sed 's/^sha256://')

SSH_PORT=$((30000 + RANDOM % 20000))
SSH_FIFO="$WORK/ssh-ready"; mkfifo "$SSH_FIFO"
python3 - "$SSH_PORT" "$SSH_FIFO" <<'PY' &
import socket, sys
port = int(sys.argv[1]); fifo = sys.argv[2]
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port)); s.listen(1)
open(fifo, "w").write("ready\n")
c, _ = s.accept()
c.send(b"SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2\r\n")
c.close(); s.close()
PY
SSH_PID=$!
read READY < "$SSH_FIFO"

LISTEN_PORT=$((30000 + RANDOM % 20000))
PS_KEY_DIR="$KDIR" \
PS_AGENT_LISTEN_ENABLED=1 \
PS_AGENT_LISTEN_PORT="$LISTEN_PORT" \
PS_AGENT_LISTEN_KEY="agent" \
PS_AGENT_AUTHORIZED_DIR="$ADIR" \
PS_PACKETSONDE_BIN="$CLI" \
"$DRIVER" >"$WORK/driver.log" 2>&1 &
DRIVER_PID=$!

cleanup() {
    kill $SSH_PID    2>/dev/null || true
    kill $DRIVER_PID 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

for i in $(seq 1 30); do
    if nc -z 127.0.0.1 "$LISTEN_PORT" 2>/dev/null; then break; fi
    sleep 0.1
done

cat > "$AGENTS_CFG" <<EOF
[agents.testagent]
address = "127.0.0.1:$LISTEN_PORT"
key_fingerprint = "sha256:$AGENT_FPR"
EOF

set +e
PS_AGENTS_TOML="$AGENTS_CFG" PS_KEY_DIR="$KDIR" \
    "$CLI" --jsonl --fail-on 'severity>=medium' --via testagent \
    audit ssh "127.0.0.1:$SSH_PORT" >"$WORK/out.jsonl" 2>/dev/null
RC=$?
set -e

if [ "$RC" -ne 3 ]; then
    echo "FAIL: expected exit 3 (--fail-on severity>=medium tripped via passthrough), got $RC"
    echo "OUTPUT:"; cat "$WORK/out.jsonl"
    exit 1
fi
grep -q '"kind":"ssh.old_version"' "$WORK/out.jsonl" \
    || { echo "FAIL: missing ssh.old_version in stream"; exit 1; }

echo "test_via_fail_on: OK"
