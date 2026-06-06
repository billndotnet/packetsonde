#!/usr/bin/env bash
# Mock unauthenticated Elasticsearch returning a cluster info JSON on
# GET /. Asserts elasticsearch.metadata and elasticsearch.unauthenticated.
set -e

BUILD_DIR="${PS_BUILD_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/build}"
CLI="$BUILD_DIR/src/cli/packetsonde"
if [ ! -x "$CLI" ]; then echo "skip: $CLI not built"; exit 77; fi
if ! command -v python3 >/dev/null 2>&1; then echo "skip: no python3"; exit 77; fi

PORT="${PS_TEST_ES_PORT:-$((30000 + RANDOM % 20000))}"
READY_FIFO=$(mktemp -u); mkfifo "$READY_FIFO"

python3 - "$PORT" "$READY_FIFO" <<'PY' &
import socket, sys
port = int(sys.argv[1]); fifo = sys.argv[2]
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port)); s.listen(1)
open(fifo, "w").write("ready\n")
c, _ = s.accept()
buf = b""
while b"\r\n\r\n" not in buf:
    chunk = c.recv(1024)
    if not chunk: break
    buf += chunk
body = (b'{"name":"mock-node","cluster_name":"packetsonde-test",'
        b'"cluster_uuid":"AAAAAAAAAAAAAAAAAAAAAA",'
        b'"version":{"number":"8.10.0","build_flavor":"default"},'
        b'"tagline":"You Know, for Search"}')
resp = (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        + f"Content-Length: {len(body)}\r\n".encode()
        + b"Connection: close\r\n\r\n" + body)
c.send(resp)
c.close(); s.close()
PY
MOCK_PID=$!
cleanup() { kill $MOCK_PID 2>/dev/null || true; rm -f "$READY_FIFO"; }
trap cleanup EXIT
read READY < "$READY_FIFO"

OUT="$("$CLI" --jsonl audit elasticsearch "127.0.0.1:$PORT" 2>/dev/null || true)"
fail() { echo "FAIL: $1"; echo "OUTPUT:"; echo "$OUT"; exit 1; }
echo "$OUT" | grep -q '"kind":"elasticsearch.metadata"'        || fail "missing elasticsearch.metadata"
echo "$OUT" | grep -q '"kind":"elasticsearch.unauthenticated"' || fail "missing elasticsearch.unauthenticated"
echo "$OUT" | grep -q 'packetsonde-test'                       || fail "missing cluster_name"
echo "$OUT" | grep -q '8.10.0'                                 || fail "missing version"
echo "test_audit_elasticsearch: OK"
