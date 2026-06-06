#!/usr/bin/env bash
# Mock Redis server that responds to INFO with a stats blob (no NOAUTH).
# Asserts redis.metadata and redis.noauth findings.
set -e

BUILD_DIR="${PS_BUILD_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/build}"
CLI="$BUILD_DIR/src/cli/packetsonde"
if [ ! -x "$CLI" ]; then echo "skip: $CLI not built"; exit 77; fi
if ! command -v python3 >/dev/null 2>&1; then echo "skip: no python3"; exit 77; fi

PORT="${PS_TEST_REDIS_PORT:-$((30000 + RANDOM % 20000))}"
READY_FIFO=$(mktemp -u); mkfifo "$READY_FIFO"

python3 - "$PORT" "$READY_FIFO" <<'PY' &
import socket, sys
port = int(sys.argv[1]); fifo = sys.argv[2]
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port)); s.listen(1)
open(fifo, "w").write("ready\n")
c, _ = s.accept()
# Read INFO command (one line, ends with \r\n)
buf = b""
while b"\r\n" not in buf: buf += c.recv(256)
# Reply with a RESP bulk string blob containing INFO output
info = (b"# Server\r\nredis_version:7.0.5\r\nredis_mode:standalone\r\n"
        b"os:Linux 6.1.0 x86_64\r\n# Clients\r\nconnected_clients:1\r\n")
hdr = f"${len(info)}\r\n".encode()
c.send(hdr + info + b"\r\n")
c.close(); s.close()
PY
MOCK_PID=$!
cleanup() { kill $MOCK_PID 2>/dev/null || true; rm -f "$READY_FIFO"; }
trap cleanup EXIT
read READY < "$READY_FIFO"

OUT="$("$CLI" --jsonl audit redis "127.0.0.1:$PORT" 2>/dev/null || true)"
fail() { echo "FAIL: $1"; echo "OUTPUT:"; echo "$OUT"; exit 1; }
echo "$OUT" | grep -q '"kind":"redis.metadata"' || fail "missing redis.metadata"
echo "$OUT" | grep -q '"kind":"redis.noauth"'   || fail "missing redis.noauth"
echo "$OUT" | grep -q '7.0.5'                   || fail "missing version"
echo "test_audit_redis: OK"
