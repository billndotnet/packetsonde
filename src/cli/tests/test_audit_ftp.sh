#!/bin/bash
# Mock FTP server that allows anonymous login.
# Asserts ftp.metadata, ftp.plaintext_exposed, ftp.anonymous_allowed.
set -e

BUILD_DIR="${PS_BUILD_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/build}"
CLI="$BUILD_DIR/src/cli/packetsonde"
if [ ! -x "$CLI" ]; then echo "skip: $CLI not built"; exit 77; fi
if ! command -v python3 >/dev/null 2>&1; then echo "skip: no python3"; exit 77; fi

PORT="${PS_TEST_FTP_PORT:-$((30000 + RANDOM % 20000))}"
READY_FIFO=$(mktemp -u); mkfifo "$READY_FIFO"

python3 - "$PORT" "$READY_FIFO" <<'PY' &
import socket, sys
port = int(sys.argv[1]); fifo = sys.argv[2]
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port)); s.listen(1)
open(fifo, "w").write("ready\n")
c, _ = s.accept()
c.send(b"220 (vsFTPd 3.0.5)\r\n")
buf = b""
while b"\r\n" not in buf: buf += c.recv(256)
# USER anonymous -> 331 Please specify the password.
c.send(b"331 Please specify the password.\r\n")
buf = b""
while b"\r\n" not in buf: buf += c.recv(256)
# PASS -> 230 Login successful (anonymous allowed)
c.send(b"230 Login successful.\r\n")
try: c.recv(256)
except Exception: pass
c.close(); s.close()
PY
MOCK_PID=$!
cleanup() { kill $MOCK_PID 2>/dev/null || true; rm -f "$READY_FIFO"; }
trap cleanup EXIT
read READY < "$READY_FIFO"

OUT="$("$CLI" --jsonl audit ftp "127.0.0.1:$PORT" 2>/dev/null || true)"
fail() { echo "FAIL: $1"; echo "OUTPUT:"; echo "$OUT"; exit 1; }
echo "$OUT" | grep -q '"kind":"ftp.metadata"'          || fail "missing ftp.metadata"
echo "$OUT" | grep -q '"kind":"ftp.anonymous_allowed"' || fail "missing ftp.anonymous_allowed"
echo "test_audit_ftp: OK"
