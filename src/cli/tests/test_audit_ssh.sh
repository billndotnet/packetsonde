#!/bin/bash
# Integration test: spin up a one-shot mock SSH server that sends an
# OpenSSH 6.0 banner (old, should flag), run packetsonde audit ssh,
# assert the expected findings.
set -e

BUILD_DIR="${PS_BUILD_DIR:-/Users/billn/packetsonde/build}"
CLI="$BUILD_DIR/src/cli/packetsonde"

if [ ! -x "$CLI" ]; then
    echo "skip: $CLI not built"
    exit 77
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "skip: no python3"
    exit 77
fi

PORT="${PS_TEST_SSH_PORT:-$((30000 + RANDOM % 20000))}"
READY_FIFO=$(mktemp -u)
mkfifo "$READY_FIFO"

python3 - "$PORT" "$READY_FIFO" <<'PY' &
import socket, sys, os
port = int(sys.argv[1])
ready_fifo = sys.argv[2]
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
s.listen(1)
# Signal readiness via the FIFO (blocks until the test opens its read end).
with open(ready_fifo, "w") as f:
    f.write("ready\n")
c, _ = s.accept()
c.send(b"SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2\r\n")
c.close()
s.close()
PY
MOCK_PID=$!
cleanup() { kill $MOCK_PID 2>/dev/null || true; rm -f "$READY_FIFO"; }
trap cleanup EXIT

# Block until the mock signals it's listening.
read READY < "$READY_FIFO"

OUT="$("$CLI" --jsonl audit ssh "127.0.0.1:$PORT" 2>/dev/null || true)"

fail() { echo "FAIL: $1"; echo "OUTPUT:"; echo "$OUT"; exit 1; }
echo "$OUT" | grep -q '"kind":"ssh.metadata"'    || fail "missing ssh.metadata"
echo "$OUT" | grep -q '"kind":"ssh.old_version"' || fail "missing ssh.old_version"
echo "$OUT" | grep -q 'OpenSSH_6.0p1'             || fail "missing OpenSSH 6.0 in evidence"

echo "test_audit_ssh: OK"
