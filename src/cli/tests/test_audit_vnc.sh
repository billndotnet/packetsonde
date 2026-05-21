#!/bin/bash
# Mock VNC server speaking RFB 003.008 that advertises three security
# types: None(1), VNC(2), TLS(18). Asserts vnc.metadata + vnc.exposed +
# vnc.no_auth (because type 1 is offered).
set -e

BUILD_DIR="${PS_BUILD_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/build}"
CLI="$BUILD_DIR/src/cli/packetsonde"
if [ ! -x "$CLI" ]; then echo "skip: $CLI not built"; exit 77; fi
if ! command -v python3 >/dev/null 2>&1; then echo "skip: no python3"; exit 77; fi

PORT="${PS_TEST_VNC_PORT:-$((30000 + RANDOM % 20000))}"
READY_FIFO=$(mktemp -u); mkfifo "$READY_FIFO"

python3 - "$PORT" "$READY_FIFO" <<'PY' &
import socket, sys
port = int(sys.argv[1]); fifo = sys.argv[2]
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port)); s.listen(1)
open(fifo, "w").write("ready\n")
c, _ = s.accept()
# 12-byte RFB ProtocolVersion
c.send(b"RFB 003.008\n")
# Read client's version reply
buf = b""
while len(buf) < 12:
    chunk = c.recv(12 - len(buf))
    if not chunk: break
    buf += chunk
# Security types: count=3, then [None=1, VNC=2, TLS=18]
c.send(bytes([3, 1, 2, 18]))
c.close(); s.close()
PY
MOCK_PID=$!
cleanup() { kill $MOCK_PID 2>/dev/null || true; rm -f "$READY_FIFO"; }
trap cleanup EXIT
read READY < "$READY_FIFO"

OUT="$("$CLI" --jsonl audit vnc "127.0.0.1:$PORT" 2>/dev/null || true)"
fail() { echo "FAIL: $1"; echo "OUTPUT:"; echo "$OUT"; exit 1; }
echo "$OUT" | grep -q '"kind":"vnc.metadata"' || fail "missing vnc.metadata"
echo "$OUT" | grep -q '"kind":"vnc.exposed"'  || fail "missing vnc.exposed"
echo "$OUT" | grep -q '"kind":"vnc.no_auth"'  || fail "missing vnc.no_auth (server offered type 1)"
echo "$OUT" | grep -q 'RFB 003.008'           || fail "missing protocol version"
echo "test_audit_vnc: OK"
