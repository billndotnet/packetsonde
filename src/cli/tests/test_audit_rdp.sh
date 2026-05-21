#!/bin/bash
# Integration test: mock RDP server that returns an X.224 Connection
# Confirm with RDP_NEG_RSP selecting plain RDP (no NLA). Asserts
# rdp.metadata, rdp.exposed, rdp.no_nla findings.
set -e

BUILD_DIR="${PS_BUILD_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/build}"
CLI="$BUILD_DIR/src/cli/packetsonde"

if [ ! -x "$CLI" ]; then
    echo "skip: $CLI not built"
    exit 77
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "skip: no python3"
    exit 77
fi

PORT="${PS_TEST_RDP_PORT:-$((30000 + RANDOM % 20000))}"
READY_FIFO=$(mktemp -u)
mkfifo "$READY_FIFO"

python3 - "$PORT" "$READY_FIFO" <<'PY' &
import socket, sys
port = int(sys.argv[1])
ready_fifo = sys.argv[2]
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
s.listen(1)
with open(ready_fifo, "w") as f:
    f.write("ready\n")
c, _ = s.accept()
# Drain the X.224 ConnReq (19 bytes for our auditor)
c.recv(1024)
# Build response:
#   TPKT: 03 00 00 13           -- len 19
#   X.224 ConnConf: 0e d0 00 00 00 00 00
#   RDP_NEG_RSP:    02 00 08 00 00 00 00 00   -- type=2, flags=0, len=8,
#                                                selectedProtocol = 0 (RDP)
resp = bytes([
    0x03, 0x00, 0x00, 0x13,
    0x0e, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00
])
c.send(resp)
c.close()
s.close()
PY
MOCK_PID=$!
cleanup() { kill $MOCK_PID 2>/dev/null || true; rm -f "$READY_FIFO"; }
trap cleanup EXIT

read READY < "$READY_FIFO"

OUT="$("$CLI" --jsonl audit rdp "127.0.0.1:$PORT" 2>/dev/null || true)"

fail() { echo "FAIL: $1"; echo "OUTPUT:"; echo "$OUT"; exit 1; }
echo "$OUT" | grep -q '"kind":"rdp.metadata"' || fail "missing rdp.metadata"
echo "$OUT" | grep -q '"kind":"rdp.exposed"'  || fail "missing rdp.exposed"
echo "$OUT" | grep -q '"kind":"rdp.no_nla"'   || fail "missing rdp.no_nla"
echo "$OUT" | grep -q '"selected_protocol":"RDP"' || fail "expected selected_protocol=RDP"

echo "test_audit_rdp: OK"
