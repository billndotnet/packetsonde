#!/bin/bash
# Integration test: mock Kafka broker that handles ApiVersions and Metadata
# requests, returning one broker and zero topics. Asserts kafka.metadata and
# kafka.unauthenticated findings.
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

PORT="${PS_TEST_KAFKA_PORT:-$((30000 + RANDOM % 20000))}"
READY_FIFO=$(mktemp -u)
mkfifo "$READY_FIFO"

python3 - "$PORT" "$READY_FIFO" <<'PY' &
import socket, struct, sys
port = int(sys.argv[1])
ready_fifo = sys.argv[2]
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
s.listen(1)
with open(ready_fifo, "w") as f:
    f.write("ready\n")
c, _ = s.accept()

def recv_req(c):
    sz_b = c.recv(4)
    if len(sz_b) < 4:
        return None
    n = struct.unpack(">i", sz_b)[0]
    body = b""
    while len(body) < n:
        body += c.recv(n - len(body))
    return body

# Request 1: ApiVersions v0  (api_key=18)
req = recv_req(c)
corr1 = struct.unpack(">i", req[8:12])[0]
# Response: corr_id (4) + error_code (2) + array_count (4) + 0 entries
resp_body = struct.pack(">ihi", corr1, 0, 0)
c.send(struct.pack(">i", len(resp_body)) + resp_body)

# Request 2: Metadata v1  (api_key=3)
req = recv_req(c)
corr2 = struct.unpack(">i", req[8:12])[0]
# Build a minimal Metadata v1 response:
#   corr_id (i32)
#   brokers array: count=1, then [node_id i32, host string i16+bytes, port i32, rack nullable i16]
#   controller_id i32
#   topics array: count=0
broker = struct.pack(">i", 1)                        # count=1
broker += struct.pack(">i", 0)                       # node_id 0
host_b = b"localhost"
broker += struct.pack(">h", len(host_b)) + host_b    # host string
broker += struct.pack(">i", 9092)                    # port
broker += struct.pack(">h", -1)                      # rack null
controller_id = struct.pack(">i", 0)
topics = struct.pack(">i", 0)
resp_body = struct.pack(">i", corr2) + broker + controller_id + topics
c.send(struct.pack(">i", len(resp_body)) + resp_body)

c.close()
s.close()
PY
MOCK_PID=$!
cleanup() { kill $MOCK_PID 2>/dev/null || true; rm -f "$READY_FIFO"; }
trap cleanup EXIT

read READY < "$READY_FIFO"

OUT="$("$CLI" --jsonl audit kafka "127.0.0.1:$PORT" 2>/dev/null || true)"

fail() { echo "FAIL: $1"; echo "OUTPUT:"; echo "$OUT"; exit 1; }
echo "$OUT" | grep -q '"kind":"kafka.metadata"'        || fail "missing kafka.metadata"
echo "$OUT" | grep -q '"kind":"kafka.unauthenticated"' || fail "missing kafka.unauthenticated"
echo "$OUT" | grep -q '"brokers":1'                    || fail "expected brokers=1"

echo "test_audit_kafka: OK"
