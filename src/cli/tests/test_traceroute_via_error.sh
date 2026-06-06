#!/bin/bash
# traceroute does not support --via yet (Phase 4). It must error clearly,
# not silently run locally. No network required.
set -e
BUILD_DIR="${PS_BUILD_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/build}"
CLI="$BUILD_DIR/src/cli/packetsonde"
[ -x "$CLI" ] || { echo "skip: no CLI"; exit 77; }

out=$("$CLI" --via someagent probe traceroute 127.0.0.1 2>&1) && rc=0 || rc=$?
echo "$out"
[ "$rc" -ne 0 ] || { echo "FAIL: expected non-zero exit with --via"; exit 1; }
echo "$out" | grep -qi 'via' || { echo "FAIL: error should mention --via"; exit 1; }
echo "test_traceroute_via_error: OK"
