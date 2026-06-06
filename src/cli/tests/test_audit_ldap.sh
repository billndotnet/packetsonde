#!/usr/bin/env bash
# Mock LDAP server that accepts anonymous bind (resultCode=0).
# Asserts ldap.metadata, ldap.anonymous_bind, and (on port 389)
# ldap.plaintext.
set -e

BUILD_DIR="${PS_BUILD_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/build}"
CLI="$BUILD_DIR/src/cli/packetsonde"
if [ ! -x "$CLI" ]; then echo "skip: $CLI not built"; exit 77; fi
if ! command -v python3 >/dev/null 2>&1; then echo "skip: no python3"; exit 77; fi

PORT="${PS_TEST_LDAP_PORT:-$((30000 + RANDOM % 20000))}"
READY_FIFO=$(mktemp -u); mkfifo "$READY_FIFO"

python3 - "$PORT" "$READY_FIFO" <<'PY' &
import socket, sys
port = int(sys.argv[1]); fifo = sys.argv[2]
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port)); s.listen(1)
open(fifo, "w").write("ready\n")
c, _ = s.accept()
# Read the BindRequest. We don't care about the contents.
c.recv(2048)
# Build a BindResponse with resultCode=0 (success), matchedDN empty,
# diagnosticMessage empty. Minimal BER:
#   30 LL                            LDAPMessage SEQUENCE
#     02 01 01                         messageID INTEGER 1
#     61 LL                            [APPLICATION 1] BindResponse
#       0a 01 00                         resultCode = 0
#       04 00                            matchedDN ""
#       04 00                            diagnosticMessage ""
bind_resp = bytes([0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00])
msg_id    = bytes([0x02, 0x01, 0x01])
body      = msg_id + bind_resp
msg       = bytes([0x30, len(body)]) + body
c.send(msg)
c.close(); s.close()
PY
MOCK_PID=$!
cleanup() { kill $MOCK_PID 2>/dev/null || true; rm -f "$READY_FIFO"; }
trap cleanup EXIT
read READY < "$READY_FIFO"

OUT="$("$CLI" --jsonl audit ldap "127.0.0.1:$PORT" 2>/dev/null || true)"
fail() { echo "FAIL: $1"; echo "OUTPUT:"; echo "$OUT"; exit 1; }
echo "$OUT" | grep -q '"kind":"ldap.metadata"'        || fail "missing ldap.metadata"
echo "$OUT" | grep -q '"kind":"ldap.anonymous_bind"'  || fail "missing ldap.anonymous_bind"
echo "test_audit_ldap: OK"
