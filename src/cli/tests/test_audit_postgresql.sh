#!/usr/bin/env bash
# Mock PostgreSQL responding 'N' to SSLRequest -> postgresql.no_ssl.
set -e

BUILD_DIR="${PS_BUILD_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/build}"
CLI="$BUILD_DIR/src/cli/packetsonde"
if [ ! -x "$CLI" ]; then echo "skip: $CLI not built"; exit 77; fi
if ! command -v python3 >/dev/null 2>&1; then echo "skip: no python3"; exit 77; fi

PORT="${PS_TEST_PG_PORT:-$((30000 + RANDOM % 20000))}"
READY_FIFO=$(mktemp -u); mkfifo "$READY_FIFO"

python3 - "$PORT" "$READY_FIFO" <<'PY' &
import socket, sys, struct
port = int(sys.argv[1]); fifo = sys.argv[2]
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port)); s.listen(1)
open(fifo, "w").write("ready\n")
c, _ = s.accept()
# Read the 8-byte SSLRequest: len(8) + magic 80877103
req = b""
while len(req) < 8:
    req += c.recv(8 - len(req))
length, magic = struct.unpack(">II", req)
assert length == 8 and magic == 80877103, f"got len={length} magic={magic:#x}"
# Reply 'N' = no SSL supported
c.send(b"N")
c.close(); s.close()
PY
MOCK_PID=$!
cleanup() { kill $MOCK_PID 2>/dev/null || true; rm -f "$READY_FIFO"; }
trap cleanup EXIT
read READY < "$READY_FIFO"

OUT="$("$CLI" --jsonl audit postgresql "127.0.0.1:$PORT" 2>/dev/null || true)"
fail() { echo "FAIL: $1"; echo "OUTPUT:"; echo "$OUT"; exit 1; }
echo "$OUT" | grep -q '"kind":"postgresql.metadata"' || fail "missing postgresql.metadata"
echo "$OUT" | grep -q '"kind":"postgresql.no_ssl"'   || fail "missing postgresql.no_ssl"
echo "test_audit_postgresql: OK"
