#!/usr/bin/env bash
# Mock HAProxy: replies with a Server: HAProxy header on / and serves the
# stats-report HTML on /stats. Asserts haproxy.metadata + haproxy.stats_exposed.
set -e

BUILD_DIR="${PS_BUILD_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/build}"
CLI="$BUILD_DIR/src/cli/packetsonde"
if [ ! -x "$CLI" ]; then echo "skip: $CLI not built"; exit 77; fi
if ! command -v python3 >/dev/null 2>&1; then echo "skip: no python3"; exit 77; fi

PORT="${PS_TEST_HAPROXY_PORT:-$((30000 + RANDOM % 20000))}"
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
    if b" /stats " in line:
        body = b"<html><head><title>Statistics Report for pid 1234</title></head>"
        body += b"<body>HAProxy Statistics Report</body></html>"
        resp = (b"HTTP/1.1 200 OK\r\nServer: HAProxy\r\n"
                b"Content-Type: text/html\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n" + body)
    else:
        body = b"<html>hi</html>"
        resp = (b"HTTP/1.1 200 OK\r\nServer: HAProxy\r\n"
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

OUT="$("$CLI" --jsonl audit haproxy "127.0.0.1:$PORT" 2>/dev/null || true)"
fail() { echo "FAIL: $1"; echo "OUTPUT:"; echo "$OUT"; exit 1; }
echo "$OUT" | grep -q '"kind":"haproxy.metadata"'      || fail "missing haproxy.metadata"
echo "$OUT" | grep -q '"detected":true'                || fail "expected detected:true"
echo "$OUT" | grep -q '"kind":"haproxy.stats_exposed"' || fail "missing haproxy.stats_exposed"
echo "test_audit_haproxy: OK"
