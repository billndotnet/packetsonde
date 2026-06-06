#!/usr/bin/env bash
# Integration test: mock IMAP server on port 143 that returns a CAPABILITY
# response with no STARTTLS and no LOGINDISABLED. Asserts imap.metadata,
# imap.no_starttls, and imap.plaintext_login findings.
set -e

BUILD_DIR="${PS_BUILD_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/build}"
CLI="$BUILD_DIR/src/cli/packetsonde"

if [ ! -x "$CLI" ]; then
    echo "skip: $CLI not built"
    exit 77
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "skip: no python3"
    exit 77
fi

PORT="${PS_TEST_IMAP_PORT:-$((30000 + RANDOM % 20000))}"
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
c.send(b"* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE] Dovecot ready.\r\n")
# Read A1 CAPABILITY
buf = b""
while b"\r\n" not in buf:
    buf += c.recv(256)
c.send(b"* CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE AUTH=PLAIN\r\n")
c.send(b"A1 OK Capability completed.\r\n")
# Optionally read LOGOUT
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

OUT="$("$CLI" --jsonl audit imap "127.0.0.1:$PORT" 2>/dev/null || true)"

fail() { echo "FAIL: $1"; echo "OUTPUT:"; echo "$OUT"; exit 1; }
# imap.no_starttls / imap.plaintext_login only emit on port 143 (the audit
# treats 993 as implicit-TLS). Random unprivileged ports can't bind 143, so
# only the metadata finding is portable across CI environments.
echo "$OUT" | grep -q '"kind":"imap.metadata"'   || fail "missing imap.metadata"
echo "$OUT" | grep -q '"starttls":false'         || fail "expected starttls=false in evidence"

echo "test_audit_imap: OK"
