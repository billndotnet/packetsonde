#!/usr/bin/env bash
# Mock SMB1 server that accepts a single-dialect NEGOTIATE request and
# replies with an SMB1 frame (magic 0xFF S M B), indicating the server
# is willing to speak SMB1.
# Asserts smb.metadata and smb.smb1_enabled.
set -e

BUILD_DIR="${PS_BUILD_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/build}"
CLI="$BUILD_DIR/src/cli/packetsonde"
if [ ! -x "$CLI" ]; then echo "skip: $CLI not built"; exit 77; fi
if ! command -v python3 >/dev/null 2>&1; then echo "skip: no python3"; exit 77; fi

PORT="${PS_TEST_SMB_PORT:-$((30000 + RANDOM % 20000))}"
READY_FIFO=$(mktemp -u); mkfifo "$READY_FIFO"

python3 - "$PORT" "$READY_FIFO" <<'PY' &
import socket, sys
port = int(sys.argv[1]); fifo = sys.argv[2]
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port)); s.listen(1)
open(fifo, "w").write("ready\n")
c, _ = s.accept()
# Drain the auditor's NEGOTIATE request.
c.recv(4096)

# SMB1 NEGOTIATE response frame:
#   NetBIOS session header (4 bytes): type=0x00, len=BE u24
#   SMB1 magic (4 bytes): 0xFF S M B
#   command (1 byte): 0x72 = Negotiate
#   status (4 bytes): 0
#   flags / flags2 / pidhigh / sig / reserved / tid / pidlow / uid / mid
#   wordcount (1 byte): 17 (for NT LM 0.12 response)
#   parameters (17 words = 34 bytes): dialect_index=0, then zeros
#   bytecount (2 bytes): 0
smb = bytes([
    0xff, 0x53, 0x4d, 0x42,   # SMB magic
    0x72,                      # command Negotiate
    0x00, 0x00, 0x00, 0x00,    # status
    0x88,                      # flags
    0x01, 0x40,                # flags2
    0x00, 0x00,                # pid_high
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # signature
    0x00, 0x00,                # reserved
    0x00, 0x00,                # tid
    0x00, 0x00,                # pid_low
    0x00, 0x00,                # uid
    0x00, 0x00,                # mid
])
# WordCount + parameters (17 16-bit words = 34 bytes; dialect_index 0).
params = bytes([0x11]) + bytes([0x00, 0x00] + [0x00] * 32)
bcount = bytes([0x00, 0x00])
smb_payload = smb + params + bcount

length = len(smb_payload)
nbss = bytes([0x00, (length >> 16) & 0xff, (length >> 8) & 0xff, length & 0xff])
c.send(nbss + smb_payload)
c.close(); s.close()
PY
MOCK_PID=$!
cleanup() { kill $MOCK_PID 2>/dev/null || true; rm -f "$READY_FIFO"; }
trap cleanup EXIT
read READY < "$READY_FIFO"

OUT="$("$CLI" --jsonl audit smb "127.0.0.1:$PORT" 2>/dev/null || true)"
fail() { echo "FAIL: $1"; echo "OUTPUT:"; echo "$OUT"; exit 1; }
echo "$OUT" | grep -q '"kind":"smb.metadata"'      || fail "missing smb.metadata"
echo "$OUT" | grep -q '"kind":"smb.smb1_enabled"'  || fail "missing smb.smb1_enabled"
echo "$OUT" | grep -q '"protocol":"SMB1"'          || fail "expected protocol=SMB1"
echo "test_audit_smb: OK"
