#!/bin/bash
# Mock nginx: GET / returns "Server: nginx/1.25.3", GET /nginx_status
# returns the canonical stub_status_module body. Asserts nginx.metadata,
# nginx.version_disclosed, and nginx.status_exposed.
set -e

BUILD_DIR="${PS_BUILD_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/build}"
CLI="$BUILD_DIR/src/cli/packetsonde"
if [ ! -x "$CLI" ]; then echo "skip: $CLI not built"; exit 77; fi
if ! command -v python3 >/dev/null 2>&1; then echo "skip: no python3"; exit 77; fi

PORT="${PS_TEST_NGINX_PORT:-$((30000 + RANDOM % 20000))}"
READY_FIFO=$(mktemp -u); mkfifo "$READY_FIFO"

python3 - "$PORT" "$READY_FIFO" <<'PY' &
import socket, sys
port = int(sys.argv[1]); fifo = sys.argv[2]
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port)); s.listen(2)
open(fifo, "w").write("ready\n")
for _ in range(2):
    c, _ = s.accept()
    req = b""
    while b"\r\n\r\n" not in req:
        chunk = c.recv(4096)
        if not chunk: break
        req += chunk
    line = req.split(b"\r\n", 1)[0]
    if b" /nginx_status " in line:
        body = (b"Active connections: 12 \n"
                b"server accepts handled requests\n"
                b" 100 100 250 \n"
                b"Reading: 0 Writing: 1 Waiting: 11 \n")
        resp = (b"HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\n"
                b"Content-Type: text/plain\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n" + body)
    else:
        body = b"<html>hi</html>"
        resp = (b"HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n" + body)
    c.sendall(resp)
    c.close()
s.close()
PY
MOCK_PID=$!
cleanup() { kill $MOCK_PID 2>/dev/null || true; rm -f "$READY_FIFO"; }
trap cleanup EXIT
read READY < "$READY_FIFO"

OUT="$("$CLI" --jsonl audit nginx "127.0.0.1:$PORT" 2>/dev/null || true)"
fail() { echo "FAIL: $1"; echo "OUTPUT:"; echo "$OUT"; exit 1; }
echo "$OUT" | grep -q '"kind":"nginx.metadata"'           || fail "missing nginx.metadata"
echo "$OUT" | grep -q '"detected":true'                   || fail "expected detected:true"
echo "$OUT" | grep -q '"version":"1.25.3"'                || fail "expected version 1.25.3"
echo "$OUT" | grep -q '"kind":"nginx.version_disclosed"'  || fail "missing nginx.version_disclosed"
echo "$OUT" | grep -q '"kind":"nginx.status_exposed"'     || fail "missing nginx.status_exposed"
echo "test_audit_nginx: OK"
