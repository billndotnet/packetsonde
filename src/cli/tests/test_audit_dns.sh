#!/bin/bash
# Mock DNS server that answers version.bind CHAOS TXT with "mock-bind 1.0".
# Asserts dns.version_leak.
set -e

BUILD_DIR="${PS_BUILD_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/build}"
CLI="$BUILD_DIR/src/cli/packetsonde"
if [ ! -x "$CLI" ]; then echo "skip: $CLI not built"; exit 77; fi
if ! command -v python3 >/dev/null 2>&1; then echo "skip: no python3"; exit 77; fi

PORT="${PS_TEST_DNS_PORT:-$((30000 + RANDOM % 20000))}"
READY_FIFO=$(mktemp -u); mkfifo "$READY_FIFO"

python3 - "$PORT" "$READY_FIFO" <<'PY' &
import socket, sys, struct
port = int(sys.argv[1]); fifo = sys.argv[2]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
open(fifo, "w").write("ready\n")
# Two probes: version.bind CHAOS TXT (qtype 16 / qclass 3), then an
# A query for the recursion check. Reply to both.
for _ in range(2):
    data, addr = s.recvfrom(2048)
    txid = data[:2]
    # Parse the question section to discover qtype/qclass.
    qd = data[12:]
    # Walk labels to find the end of QNAME
    i = 0
    while i < len(qd) and qd[i] != 0:
        i += qd[i] + 1
    qtype  = struct.unpack(">H", qd[i+1:i+3])[0]
    qclass = struct.unpack(">H", qd[i+3:i+5])[0]
    qname_end = i + 5
    qsection = qd[:qname_end]

    if qtype == 16 and qclass == 3:  # version.bind CHAOS TXT
        # Header: id, flags(QR=1 AA=1 RCODE=0), QDCOUNT=1, ANCOUNT=1, NS=0, AR=0
        hdr = txid + struct.pack(">HHHHH", 0x8400, 1, 1, 0, 0)
        # Answer: NAME=ptr to qname (0xC00C), TYPE=16, CLASS=3, TTL=0,
        #         RDLENGTH=12, RDATA=<txt-len><"mock-bind 1.0">
        txt = b"mock-bind 1.0"
        rdata = bytes([len(txt)]) + txt
        ans = b"\xc0\x0c" + struct.pack(">HHIH", 16, 3, 0, len(rdata)) + rdata
        s.sendto(hdr + qsection + ans, addr)
    else:
        # Plain refused-style empty answer for recursion check.
        hdr = txid + struct.pack(">HHHHH", 0x8485, 1, 0, 0, 0)  # RCODE=5 REFUSED
        s.sendto(hdr + qsection, addr)
s.close()
PY
MOCK_PID=$!
cleanup() { kill $MOCK_PID 2>/dev/null || true; rm -f "$READY_FIFO"; }
trap cleanup EXIT
read READY < "$READY_FIFO"

# Audit dns takes the DNS server as a raw IP arg.
OUT="$("$CLI" --jsonl audit dns "127.0.0.1:$PORT" 2>/dev/null || true)"
fail() { echo "FAIL: $1"; echo "OUTPUT:"; echo "$OUT"; exit 1; }
echo "$OUT" | grep -q '"kind":"dns.version_leak"' || fail "missing dns.version_leak"
echo "$OUT" | grep -q 'mock-bind 1.0'              || fail "missing version string"
echo "test_audit_dns: OK"
