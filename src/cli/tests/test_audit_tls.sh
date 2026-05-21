#!/bin/bash
# Integration test: spin up an openssl s_server on a free port with weak
# parameters, run `packetsonde audit tls 127.0.0.1:PORT`, assert findings.
#
# The audit client skips loading the system openssl.cnf and sets
# SECLEVEL=0 per-context so it can probe ancient protocols / weak ciphers
# regardless of the host's default policy.
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${PS_BUILD_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/build}"
CLI="$BUILD_DIR/src/cli/packetsonde"

if [ ! -x "$CLI" ]; then
    echo "skip: $CLI not built"
    exit 77
fi
if ! command -v openssl >/dev/null 2>&1; then
    echo "skip: no openssl"
    exit 77
fi

# Pick an ephemeral-ish port to avoid TIME_WAIT collisions across runs.
PORT="${PS_TEST_PORT:-$((30000 + RANDOM % 20000))}"

read CRT KEY < <("$HERE/test_audit_tls_cert.sh")
cleanup() { kill "$SERVER_PID" 2>/dev/null || true; rm -f "$CRT" "$KEY"; }
trap cleanup EXIT

openssl s_server \
    -cert "$CRT" -key "$KEY" \
    -port "$PORT" \
    -tls1 \
    -cipher 'NULL-SHA:DEFAULT:@SECLEVEL=0' \
    -quiet \
    >/dev/null 2>&1 &
SERVER_PID=$!

# Wait up to 3s for the server to be ready.
for _ in 1 2 3 4 5 6; do
    if echo Q | openssl s_client -connect "127.0.0.1:$PORT" -tls1 >/dev/null 2>&1; then
        break
    fi
    sleep 0.5
done

OUT="$("$CLI" --jsonl audit tls "127.0.0.1:$PORT" 2>/dev/null || true)"

fail() { echo "FAIL: $1"; echo "OUTPUT:"; echo "$OUT"; exit 1; }
echo "$OUT" | grep -q '"kind":"tls.weak_protocol"'     || fail "missing tls.weak_protocol"
echo "$OUT" | grep -q '"kind":"tls.weak_cipher"'       || fail "missing tls.weak_cipher"
echo "$OUT" | grep -q '"kind":"tls.self_signed"'       || fail "missing tls.self_signed"
echo "$OUT" | grep -q '"kind":"tls.weak_signature"'    || fail "missing tls.weak_signature"
echo "$OUT" | grep -q '"kind":"tls.weak_key"'          || fail "missing tls.weak_key"
echo "$OUT" | grep -q '"kind":"tls.hostname_mismatch"' || fail "missing tls.hostname_mismatch"
echo "$OUT" | grep -q '"kind":"tls.expiring_cert"'     || fail "missing tls.expiring_cert"

echo "test_audit_tls: OK"
