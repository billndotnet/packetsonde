#!/bin/bash
# Integration test: mock agent that uses raw socket -- skipped here as it
# needs root. Instead we run a Python responder that *does* bind a UDP
# port and listens on the broadcast destination port, signs a reply with
# its own Ed25519 key (added to the CLI's authorized set), and answers.
#
# This proves the full sign/verify/replay path end-to-end on loopback,
# even though a real deployment uses pcap on the agent side. The pcap
# integration is tested separately (or in the daemon).
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
# Need the cryptography package for Ed25519.
if ! python3 -c 'import cryptography.hazmat.primitives.asymmetric.ed25519' 2>/dev/null; then
    echo "skip: python cryptography package not installed"
    exit 77
fi

KDIR=$(mktemp -d)
trap "rm -rf $KDIR" EXIT
export PS_KEY_DIR="$KDIR"

# Generate a CLI key. The Python responder will read this key's pubkey to
# verify the probe; the responder uses *its own* key for the reply.
"$CLI" key generate --name default >/dev/null

PORT=$((30000 + RANDOM % 20000))
READY_FIFO=$(mktemp -u)
mkfifo "$READY_FIFO"

CLI_PUB="$KDIR/default.pub"
AGENT_OUT=$(mktemp)

python3 - "$PORT" "$READY_FIFO" "$CLI_PUB" "$AGENT_OUT" <<'PY' &
import socket, struct, sys, os, time
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

port = int(sys.argv[1])
ready_fifo = sys.argv[2]
cli_pub_path = sys.argv[3]
agent_pub_out = sys.argv[4]

cli_pub = open(cli_pub_path, "rb").read()
agent_sk = ed25519.Ed25519PrivateKey.generate()
agent_pk = agent_sk.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw)
open(agent_pub_out, "wb").write(agent_pk)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.bind(("0.0.0.0", port))
with open(ready_fifo, "w") as f:
    f.write("ready\n")

data, addr = s.recvfrom(2048)
# Verify probe: magic, sig prefix = 80 bytes
assert data[:4] == b"PSDP", "bad magic"
probe_pub = data[48:80]
sig = data[80:144]
prefix = data[:80]
# Trust the probe only if signed by cli_pub
pk = ed25519.Ed25519PublicKey.from_public_bytes(probe_pub)
pk.verify(sig, prefix)  # raises on failure
assert probe_pub == cli_pub, "unexpected pubkey in probe"
nonce = data[16:32]

# Build reply: magic + ver + flags + nonce + listen_ip(v4-mapped 127.0.0.1) +
# listen_port + agent_pub + sig
reply = bytearray()
reply += b"PSDR"
reply += bytes([0x01, 0x00])
reply += nonce
listen_ip = bytes(10) + bytes([0xff, 0xff, 127, 0, 0, 1])  # v4-mapped 127.0.0.1
reply += listen_ip
reply += struct.pack(">H", 7421)
reply += agent_pk
prefix2 = bytes(reply)
sig2 = agent_sk.sign(prefix2)
reply += sig2
assert len(reply) == 136

# Reply unicast to the probe's source.
s.sendto(bytes(reply), addr)
s.close()
PY
MOCK_PID=$!
cleanup() { kill $MOCK_PID 2>/dev/null || true; rm -f "$READY_FIFO"; }
trap "cleanup; rm -rf $KDIR $AGENT_OUT" EXIT

read READY < "$READY_FIFO"

# Loopback "broadcast" is fragile cross-platform; send unicast to 127.0.0.1.
# target_to_broadcast() treats a bare IP without /prefix as a host address.
OUT="$("$CLI" --jsonl discover agents 127.0.0.1 --cover-port "$PORT" --wait 2 2>/dev/null || true)"

fail() { echo "FAIL: $1"; echo "OUTPUT:"; echo "$OUT"; exit 1; }
echo "$OUT" | grep -q '"kind":"discovery.agent"'    || fail "missing discovery.agent"
echo "$OUT" | grep -q '"listen_port":7421'           || fail "missing listen_port=7421"
echo "$OUT" | grep -q '"listen_ip":"127.0.0.1"'      || fail "missing listen_ip"
echo "$OUT" | grep -q 'agent_pub_fingerprint'        || fail "missing fingerprint"

echo "test_discover_agents: OK"
