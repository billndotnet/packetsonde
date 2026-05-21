#!/bin/bash
# Integration test: mock SNMP v2c responder that accepts community "public"
# and returns a sysDescr GetResponse. Asserts snmp.metadata and
# snmp.default_community findings.
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

PORT="${PS_TEST_SNMP_PORT:-$((30000 + RANDOM % 20000))}"
READY_FIFO=$(mktemp -u)
mkfifo "$READY_FIFO"

python3 - "$PORT" "$READY_FIFO" <<'PY' &
import socket, sys, struct
port = int(sys.argv[1])
ready_fifo = sys.argv[2]

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
with open(ready_fifo, "w") as f:
    f.write("ready\n")

# Receive one GetRequest, parse the request-id, send back a GetResponse
# with sysDescr value. Tiny BER -- assumes the probe matches what audit
# snmp sends (community "public" or "private", version v1 or v2c, OID
# 1.3.6.1.2.1.1.1.0). The first packet we get is good enough.
data, addr = s.recvfrom(2048)

# Pull request-id from incoming packet. Walk past:
#   30 LL 02 01 vv 04 cl <community> a0 LL 02 04 RR RR RR RR ...
p = 0
assert data[p] == 0x30; p += 2          # outer SEQUENCE
assert data[p] == 0x02; vlen = data[p+1]; p += 2 + vlen   # version INTEGER
assert data[p] == 0x04; clen = data[p+1]; community = data[p+2:p+2+clen]; p += 2 + clen
assert data[p] == 0xa0; p += 2          # GetRequest PDU
assert data[p] == 0x02; rlen = data[p+1]; req_id = data[p+2:p+2+rlen]; p += 2 + rlen

# Build response: GetResponse with one varbind: OID + OCTET STRING sysDescr
sysdescr = b"PacketSonde-Mock SNMPd v0.1"
oid = bytes([0x2b, 6, 1, 2, 1, 1, 1, 0])
# varbind: SEQUENCE { OID, OCTET STRING }
vb_inner = bytes([0x06, len(oid)]) + oid + bytes([0x04, len(sysdescr)]) + sysdescr
vb = bytes([0x30, len(vb_inner)]) + vb_inner
# varbinds list: SEQUENCE { varbind }
vbs = bytes([0x30, len(vb)]) + vb
# PDU body: req-id INTEGER, err-status 0, err-index 0, varbinds
pdu_body = (bytes([0x02, len(req_id)]) + req_id +
            bytes([0x02, 0x01, 0x00]) +
            bytes([0x02, 0x01, 0x00]) +
            vbs)
pdu = bytes([0xa2, len(pdu_body)]) + pdu_body  # GetResponse tag 0xa2
# message: SEQUENCE { version INTEGER (echo), community OCTET STRING, PDU }
msg_body = (bytes([0x02, 0x01, 0x01]) +  # version v2c (1)
            bytes([0x04, len(community)]) + community +
            pdu)
msg = bytes([0x30, len(msg_body)]) + msg_body
s.sendto(msg, addr)
s.close()
PY
MOCK_PID=$!
cleanup() { kill $MOCK_PID 2>/dev/null || true; rm -f "$READY_FIFO"; }
trap cleanup EXIT

read READY < "$READY_FIFO"

OUT="$("$CLI" --jsonl audit snmp "127.0.0.1:$PORT" 2>/dev/null || true)"

fail() { echo "FAIL: $1"; echo "OUTPUT:"; echo "$OUT"; exit 1; }
echo "$OUT" | grep -q '"kind":"snmp.metadata"'           || fail "missing snmp.metadata"
echo "$OUT" | grep -q '"kind":"snmp.default_community"'  || fail "missing snmp.default_community"
echo "$OUT" | grep -q 'PacketSonde-Mock'                 || fail "missing sysDescr in evidence"
echo "$OUT" | grep -q '"community":"public"'             || fail "expected community=public"

echo "test_audit_snmp: OK"
