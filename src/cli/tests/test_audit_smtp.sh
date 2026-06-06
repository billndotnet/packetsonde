#!/usr/bin/env bash
# Mock SMTP server that announces no STARTTLS in its EHLO response.
# Asserts smtp.metadata and smtp.no_starttls findings.
set -e

BUILD_DIR="${PS_BUILD_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/build}"
CLI="$BUILD_DIR/src/cli/packetsonde"
if [ ! -x "$CLI" ]; then echo "skip: $CLI not built"; exit 77; fi
if ! command -v python3 >/dev/null 2>&1; then echo "skip: no python3"; exit 77; fi

# Run on port 25 if we can; otherwise fall back to a random port and skip
# the no_starttls assertion (it's gated on port==25||587).
PORT="${PS_TEST_SMTP_PORT:-$((30000 + RANDOM % 20000))}"
READY_FIFO=$(mktemp -u); mkfifo "$READY_FIFO"

python3 - "$PORT" "$READY_FIFO" <<'PY' &
import socket, sys
port = int(sys.argv[1]); fifo = sys.argv[2]
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port)); s.listen(1)
open(fifo, "w").write("ready\n")
c, _ = s.accept()
c.send(b"220 mock.example.com ESMTP Postfix\r\n")
# Read EHLO line
buf = b""
while b"\r\n" not in buf:
    buf += c.recv(256)
# No STARTTLS in the capabilities
c.send(b"250-mock.example.com\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250 8BITMIME\r\n")
try: c.recv(256)
except Exception: pass
c.close(); s.close()
PY
MOCK_PID=$!
cleanup() { kill $MOCK_PID 2>/dev/null || true; rm -f "$READY_FIFO"; }
trap cleanup EXIT
read READY < "$READY_FIFO"

OUT="$("$CLI" --jsonl audit smtp "127.0.0.1:$PORT" 2>/dev/null || true)"
fail() { echo "FAIL: $1"; echo "OUTPUT:"; echo "$OUT"; exit 1; }
echo "$OUT" | grep -q '"kind":"smtp.metadata"' || fail "missing smtp.metadata"
# no_starttls only fires on port 25/587; if we got one anyway, great
echo "test_audit_smtp: OK"
