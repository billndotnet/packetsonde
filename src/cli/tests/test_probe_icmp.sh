#!/bin/bash
# Integration test for `packetsonde probe icmp`. Pings loopback and asserts
# the reply + summary findings. Skips if the unprivileged ICMP socket cannot
# be opened (e.g. Linux env where ping_group_range excludes the test user
# and we don't have CAP_NET_RAW).
set -e

BUILD_DIR="${PS_BUILD_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/build}"
CLI="$BUILD_DIR/src/cli/packetsonde"
if [ ! -x "$CLI" ]; then echo "skip: $CLI not built"; exit 77; fi

OUT="$("$CLI" --jsonl probe icmp 127.0.0.1 -c 2 -t 500 2>&1 || true)"

# If the kernel won't give us an ICMP socket, skip rather than fail.
if echo "$OUT" | grep -q "cannot open ICMP socket"; then
    echo "skip: no unprivileged ICMP socket"; exit 77
fi

fail() { echo "FAIL: $1"; echo "OUTPUT:"; echo "$OUT"; exit 1; }
echo "$OUT" | grep -q '"kind":"probe.icmp.reply"'   || fail "missing probe.icmp.reply"
echo "$OUT" | grep -q '"kind":"probe.icmp.summary"' || fail "missing probe.icmp.summary"
echo "$OUT" | grep -q '"rtt_us":'                   || fail "missing rtt_us in evidence"
echo "test_probe_icmp: OK"
