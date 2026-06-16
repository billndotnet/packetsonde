#!/usr/bin/env bash
# Integration test for `packetsonde probe udp`. Starts a trivial python UDP
# echo server on loopback and asserts the probe classifies it as open with a
# target.ip and evidence.state=="open". Echo guarantees an application-layer
# reply, so this needs no raw socket / privileges.
set -e

BUILD_DIR="${PS_BUILD_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/build}"
CLI="$BUILD_DIR/src/cli/packetsonde"
if [ ! -x "$CLI" ]; then echo "skip: $CLI not built"; exit 77; fi
if ! command -v python3 >/dev/null 2>&1; then echo "skip: no python3"; exit 77; fi

UDP_PORT=$((30000 + RANDOM % 20000))
UDP_FIFO=$(mktemp -u); mkfifo "$UDP_FIFO"
python3 - "$UDP_PORT" "$UDP_FIFO" <<'PY' &
import socket, sys
port = int(sys.argv[1]); fifo = sys.argv[2]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
with open(fifo, "w") as f: f.write("ready\n")
data, addr = s.recvfrom(2048)
s.sendto(data if data else b"\x00", addr)
s.close()
PY
UDP_PID=$!
trap "kill $UDP_PID 2>/dev/null || true; rm -f $UDP_FIFO" EXIT
read UDP_READY < "$UDP_FIFO"

OUT="$("$CLI" --jsonl probe udp "127.0.0.1:$UDP_PORT" 2>&1 || true)"

fail() { echo "FAIL: $1"; echo "OUTPUT:"; echo "$OUT"; exit 1; }
echo "$OUT" | grep -q '"kind":"probe.udp.open"' || fail "missing probe.udp.open finding"
echo "$OUT" | grep -q '"ip":"127.0.0.1"'        || fail "missing target.ip"
echo "$OUT" | grep -q '"state":"open"'          || fail "missing evidence.state==open"
echo "test_probe_udp: OK"
