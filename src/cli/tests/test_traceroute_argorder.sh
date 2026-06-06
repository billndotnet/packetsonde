#!/bin/bash
# traceroute accepts its target before, after, or interleaved with options
# (POSIX getopt doesn't permute, so the verb handles the positional itself).
# No network/caps needed: an unresolvable target fails fast and the error echoes
# the PARSED proto/mode, so we can assert options applied regardless of position.
set -e
BUILD_DIR="${PS_BUILD_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/build}"
CLI="$BUILD_DIR/src/cli/packetsonde"
[ -x "$CLI" ] || { echo "skip: no CLI"; exit 77; }

chk() {  # chk "<args>" "<expected substring in stderr>"
    out=$("$CLI" probe traceroute $1 2>&1 || true)
    echo "$out" | grep -q "$2" || { echo "FAIL: [$1] expected [$2], got: $out"; exit 1; }
}
chk "--mode paris --max-gap 5 nope.invalid"  "mode=paris"    # options before target
chk "nope.invalid --mode paris"              "mode=paris"    # target before options
chk "--ptr nope.invalid --mode paris"        "mode=paris"    # interleaved
chk "--proto tcp nope.invalid --mode dublin" "proto=tcp"     # both, interleaved
chk "--proto tcp nope.invalid --mode dublin" "mode=dublin"
chk "nope.invalid"                           "mode=classic"  # default mode

# a second positional is rejected
"$CLI" probe traceroute a.com b.com 2>&1 | grep -q "unexpected extra argument" \
    || { echo "FAIL: extra positional not rejected"; exit 1; }
# no target -> usage, exit 2
"$CLI" probe traceroute --mode paris >/dev/null 2>&1 && { echo "FAIL: missing target should exit non-zero"; exit 1; }

echo "test_traceroute_argorder: OK"
