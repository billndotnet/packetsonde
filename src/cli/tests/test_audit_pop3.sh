#!/bin/bash
# Integration test: mock POP3 server on port 110 that returns a CAPA
# response without STLS. Asserts pop3.metadata and pop3.no_stls findings.
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

PORT="${PS_TEST_POP3_PORT:-$((30000 + RANDOM % 20000))}"
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
c.send(b"+OK Dovecot ready.\r\n")
# Read CAPA
buf = b""
while b"\r\n" not in buf:
    buf += c.recv(256)
# Multi-line CAPA response, no STLS advertised
c.send(b"+OK\r\nTOP\r\nUIDL\r\nRESP-CODES\r\nPIPELINING\r\nUSER\r\nSASL PLAIN\r\n.\r\n")
try:
    c.recv(256)
except Exception:
    pass
c.close()
s.close()
PY
MOCK_PID=$!
cleanup() { kill $MOCK_PID 2>/dev/null || true; rm -f "$READY_FIFO"; }
trap cleanup EXIT

read READY < "$READY_FIFO"

OUT="$("$CLI" --jsonl audit pop3 "127.0.0.1:$PORT" 2>/dev/null || true)"

fail() { echo "FAIL: $1"; echo "OUTPUT:"; echo "$OUT"; exit 1; }
# pop3.no_stls only emits on port 110 (the audit treats 995 as implicit-TLS).
# Random unprivileged ports can't bind 110, so only the metadata finding is
# portable across CI environments.
echo "$OUT" | grep -q '"kind":"pop3.metadata"' || fail "missing pop3.metadata"
echo "$OUT" | grep -q '"stls":false'           || fail "expected stls=false in evidence"

echo "test_audit_pop3: OK"
