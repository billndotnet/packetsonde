#!/usr/bin/env bash
# Mock MySQL/MariaDB handshake announcing version 5.5.62 (pre-8.0).
# Asserts mysql.metadata + mysql.old_version (medium, < 8.0 is EOL).
set -e

BUILD_DIR="${PS_BUILD_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/build}"
CLI="$BUILD_DIR/src/cli/packetsonde"
if [ ! -x "$CLI" ]; then echo "skip: $CLI not built"; exit 77; fi
if ! command -v python3 >/dev/null 2>&1; then echo "skip: no python3"; exit 77; fi

PORT="${PS_TEST_MYSQL_PORT:-$((30000 + RANDOM % 20000))}"
READY_FIFO=$(mktemp -u); mkfifo "$READY_FIFO"

python3 - "$PORT" "$READY_FIFO" <<'PY' &
import socket, sys, struct
port = int(sys.argv[1]); fifo = sys.argv[2]
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port)); s.listen(1)
open(fifo, "w").write("ready\n")
c, _ = s.accept()
# Handshake v10 packet: 4-byte header (len + seq) then proto_ver(10) +
# NUL-terminated server_version + connection_id(4) + scramble_1(8) +
# filler(1) + capability_flags(2) + ...
ver = b"5.5.62-MariaDB"
body = bytes([10]) + ver + b"\x00" + b"\x01\x00\x00\x00" + b"AAAAAAAA" + b"\x00" + b"\x00\x80"
# Pad to a plausible handshake size
body += b"\x21\x08\x02\x00" + b"\x0f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
length = len(body)
hdr = bytes([length & 0xff, (length >> 8) & 0xff, (length >> 16) & 0xff, 0])
c.send(hdr + body)
c.close(); s.close()
PY
MOCK_PID=$!
cleanup() { kill $MOCK_PID 2>/dev/null || true; rm -f "$READY_FIFO"; }
trap cleanup EXIT
read READY < "$READY_FIFO"

OUT="$("$CLI" --jsonl audit mysql "127.0.0.1:$PORT" 2>/dev/null || true)"
fail() { echo "FAIL: $1"; echo "OUTPUT:"; echo "$OUT"; exit 1; }
echo "$OUT" | grep -q '"kind":"mysql.metadata"'    || fail "missing mysql.metadata"
echo "$OUT" | grep -q '"kind":"mysql.old_version"' || fail "missing mysql.old_version"
echo "$OUT" | grep -q '5.5.62-MariaDB'             || fail "missing version string"
echo "test_audit_mysql: OK"
