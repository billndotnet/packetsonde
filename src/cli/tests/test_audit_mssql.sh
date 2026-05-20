#!/bin/bash
# Integration test: mock MSSQL server that returns a TDS pre-login response
# claiming version 11.0.0 (SQL Server 2012) with encryption=OFF. Asserts
# mssql.metadata, mssql.no_encryption, mssql.old_version.
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

PORT="${PS_TEST_MSSQL_PORT:-$((30000 + RANDOM % 20000))}"
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
c.recv(1024)  # drain client pre-login

# Build response body:
#   Option table:
#     00 OFFSET LEN  -- VERSION  len=6
#     01 OFFSET 0001 -- ENCRYPTION len=1
#     FF             -- terminator
#   Data:
#     VERSION:    0b 00 00 00 00 00  (major=11, minor=0, build=0)
#     ENCRYPTION: 00                 (off)
# Header (8) + option table (5+5+1 = 11) + payload (7) = 26
opts = bytes([
    0x00, 0x00, 11, 0x00, 0x06,    # token=0, offset=11, len=6
    0x01, 0x00, 17, 0x00, 0x01,    # token=1, offset=17, len=1
    0xff
])
data = bytes([0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
body = opts + data
total = 8 + len(body)
hdr = bytes([0x04, 0x01, (total >> 8) & 0xff, total & 0xff,
             0x00, 0x00, 0x01, 0x00])
c.send(hdr + body)
c.close()
s.close()
PY
MOCK_PID=$!
cleanup() { kill $MOCK_PID 2>/dev/null || true; rm -f "$READY_FIFO"; }
trap cleanup EXIT

read READY < "$READY_FIFO"

OUT="$("$CLI" --jsonl audit mssql "127.0.0.1:$PORT" 2>/dev/null || true)"

fail() { echo "FAIL: $1"; echo "OUTPUT:"; echo "$OUT"; exit 1; }
echo "$OUT" | grep -q '"kind":"mssql.metadata"'      || fail "missing mssql.metadata"
echo "$OUT" | grep -q '"kind":"mssql.no_encryption"' || fail "missing mssql.no_encryption"
echo "$OUT" | grep -q '"kind":"mssql.old_version"'   || fail "missing mssql.old_version"
echo "$OUT" | grep -q '"version_major":11'           || fail "expected version_major=11"

echo "test_audit_mssql: OK"
