#!/bin/bash
# Mock HTTP server with no security headers -> http.metadata +
# missing_xcto / missing_frame_protection / missing_csp /
# missing_referrer_policy / server_version_leak.
set -e

BUILD_DIR="${PS_BUILD_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/build}"
CLI="$BUILD_DIR/src/cli/packetsonde"
if [ ! -x "$CLI" ]; then echo "skip: $CLI not built"; exit 77; fi
if ! command -v python3 >/dev/null 2>&1; then echo "skip: no python3"; exit 77; fi

PORT="${PS_TEST_HTTP_PORT:-$((30000 + RANDOM % 20000))}"
READY_FIFO=$(mktemp -u); mkfifo "$READY_FIFO"

python3 - "$PORT" "$READY_FIFO" <<'PY' &
import socket, sys
port = int(sys.argv[1]); fifo = sys.argv[2]
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port)); s.listen(1)
open(fifo, "w").write("ready\n")
c, _ = s.accept()
# Read until end of request headers
buf = b""
while b"\r\n\r\n" not in buf:
    chunk = c.recv(1024)
    if not chunk: break
    buf += chunk
body = b"<html><body>hi</body></html>"
resp = (
    b"HTTP/1.1 200 OK\r\n"
    b"Server: nginx/1.18.0\r\n"
    b"Content-Type: text/html\r\n"
    + f"Content-Length: {len(body)}\r\n".encode()
    + b"Connection: close\r\n\r\n" + body
)
c.send(resp)
c.close(); s.close()
PY
MOCK_PID=$!
cleanup() { kill $MOCK_PID 2>/dev/null || true; rm -f "$READY_FIFO"; }
trap cleanup EXIT
read READY < "$READY_FIFO"

OUT="$("$CLI" --jsonl audit http "http://127.0.0.1:$PORT/" 2>/dev/null || true)"
fail() { echo "FAIL: $1"; echo "OUTPUT:"; echo "$OUT"; exit 1; }
echo "$OUT" | grep -q '"kind":"http.metadata"'                  || fail "missing http.metadata"
echo "$OUT" | grep -q '"kind":"http.missing_xcto"'              || fail "missing http.missing_xcto"
echo "$OUT" | grep -q '"kind":"http.missing_frame_protection"'  || fail "missing http.missing_frame_protection"
echo "$OUT" | grep -q '"kind":"http.missing_csp"'               || fail "missing http.missing_csp"
echo "$OUT" | grep -q '"kind":"http.server_version_leak"'       || fail "missing http.server_version_leak"
echo "test_audit_http: OK"
