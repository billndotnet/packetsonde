#!/usr/bin/env bash
# Mock NTP responder. Answers the mode-3 client query with a 48-byte
# stratum-2 response, and the mode-7 monlist probe with a sizable
# (~500-byte) payload that should trip the amplification finding.
# Asserts ntp.metadata and ntp.monlist_amplification.
set -e

BUILD_DIR="${PS_BUILD_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/build}"
CLI="$BUILD_DIR/src/cli/packetsonde"
if [ ! -x "$CLI" ]; then echo "skip: $CLI not built"; exit 77; fi
if ! command -v python3 >/dev/null 2>&1; then echo "skip: no python3"; exit 77; fi

PORT="${PS_TEST_NTP_PORT:-$((30000 + RANDOM % 20000))}"
READY_FIFO=$(mktemp -u); mkfifo "$READY_FIFO"

python3 - "$PORT" "$READY_FIFO" <<'PY' &
import socket, sys
port = int(sys.argv[1]); fifo = sys.argv[2]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
open(fifo, "w").write("ready\n")

for _ in range(2):
    data, addr = s.recvfrom(2048)
    mode = data[0] & 0x07
    if mode == 3:
        # NTPv4 server response: LI=0 VN=4 Mode=4 = 0x24, stratum=2
        resp = bytes([0x24, 0x02]) + b"\x00" * 46
        s.sendto(resp, addr)
    elif mode == 7:
        # Fake mode-7 monlist reply -- 500 bytes of payload, R bit set
        # so the auditor's m>48 && !err branch fires.
        resp = bytes([0x97, 0x00, 0x03, 0x2A, 0x00, 0x06, 0x00, 0x48])
        resp += b"\x01" * (500 - 8)
        s.sendto(resp, addr)
s.close()
PY
MOCK_PID=$!
cleanup() { kill $MOCK_PID 2>/dev/null || true; rm -f "$READY_FIFO"; }
trap cleanup EXIT
read READY < "$READY_FIFO"

OUT="$("$CLI" --jsonl audit ntp "127.0.0.1:$PORT" 2>/dev/null || true)"
fail() { echo "FAIL: $1"; echo "OUTPUT:"; echo "$OUT"; exit 1; }
echo "$OUT" | grep -q '"kind":"ntp.metadata"'               || fail "missing ntp.metadata"
echo "$OUT" | grep -q '"kind":"ntp.monlist_amplification"'  || fail "missing ntp.monlist_amplification"
echo "$OUT" | grep -q '"cve":"CVE-2013-5211"'               || fail "missing CVE tag"
echo "test_audit_ntp: OK"
