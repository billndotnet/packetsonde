#!/usr/bin/env bash
# packetsonde end-to-end self-test on a single host.
#
# Brings up:
#   - a Python mock SSH server that emits an OpenSSH 6.0 banner
#   - the packetsonded agent in foreground with persistent-mode mTLS
#   - a fresh CLI keypair + agent keypair in $PWD/.selftest/
#
# Then runs:
#   1. packetsonde audit ssh <mock>          (local audit, sanity)
#   2. packetsonde --via local audit ssh <mock>  (mTLS path through the
#                                                   in-process agent)
#
# Asserts each step emits ssh.metadata + ssh.old_version, and that the
# remote run also splices via_agent=local.
#
# Cleans up the agent + mock + keys on exit.
set -e
trap 'echo; echo "=== selftest FAILED (line $LINENO) ==="' ERR

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
BUILD="${PS_BUILD_DIR:-$ROOT/build}"
CLI="$BUILD/src/cli/packetsonde"
AGENT="$BUILD/src/agent/packetsonded"

for bin in "$CLI" "$AGENT"; do
    if [ ! -x "$bin" ]; then
        echo "missing $bin -- run ./build.sh first"
        exit 1
    fi
done
command -v python3 >/dev/null 2>&1 || { echo "selftest requires python3"; exit 1; }

WORK="$(mktemp -d -t ps-selftest.XXXXXX)"
export PS_KEY_DIR="$WORK/keys"
mkdir -p "$PS_KEY_DIR/authorized"

cleanup() {
    [ -n "${AGENT_PID:-}" ] && kill "$AGENT_PID" 2>/dev/null || true
    [ -n "${MOCK_PID:-}"  ] && kill "$MOCK_PID"  2>/dev/null || true
    rm -rf "$WORK"
}
trap 'cleanup' EXIT

echo "=== packetsonde self-test ==="
echo "    workdir: $WORK"
echo

# 1. Mock SSH target.
SSH_PORT=$((30000 + RANDOM % 20000))
SSH_FIFO="$WORK/ssh-ready"; mkfifo "$SSH_FIFO"
python3 - "$SSH_PORT" "$SSH_FIFO" <<'PY' &
import socket, sys
port = int(sys.argv[1]); fifo = sys.argv[2]
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port)); s.listen(2)
open(fifo, "w").write("ready\n")
# Accept up to 2 connections (one for local audit, one for --via audit)
for _ in range(2):
    c, _ = s.accept()
    c.send(b"SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2\r\n")
    c.close()
s.close()
PY
MOCK_PID=$!
read READY < "$SSH_FIFO"
echo "mock SSH:  127.0.0.1:$SSH_PORT (OpenSSH 6.0 banner)"

# 2. Keys: CLI 'default' + agent 'agent', cross-authorized.
"$CLI" key generate --name default >/dev/null
"$CLI" key generate --name agent   >/dev/null
cp "$PS_KEY_DIR/default.pub" "$PS_KEY_DIR/authorized/cli.pub"
CLI_FPR=$("$CLI"   key fingerprint default | sed 's/^sha256://')
AGENT_FPR=$("$CLI" key fingerprint agent   | sed 's/^sha256://')
echo "cli fpr:   sha256:$CLI_FPR"
echo "agent fpr: sha256:$AGENT_FPR"

# 3. Start the agent with persistent-mode mTLS on a random port.
LISTEN_PORT=$((30000 + RANDOM % 20000))
cat > "$WORK/agent.toml" <<EOF
[agent]
user = "current"

[keys]
dir = "$PS_KEY_DIR"

[agent_listen]
mode             = "persistent"
addr             = "127.0.0.1"
port             = "$LISTEN_PORT"
key              = "agent"
authorized_dir   = "$PS_KEY_DIR/authorized"
packetsonde_bin  = "$CLI"
EOF
"$AGENT" -c "$WORK/agent.toml" >"$WORK/agent.log" 2>&1 &
AGENT_PID=$!

# Wait for the listener to bind.
for i in $(seq 1 30); do
    if nc -z 127.0.0.1 "$LISTEN_PORT" 2>/dev/null; then break; fi
    sleep 0.1
done
if ! nc -z 127.0.0.1 "$LISTEN_PORT" 2>/dev/null; then
    echo; echo "agent failed to bind. Log:"
    cat "$WORK/agent.log"
    exit 1
fi
echo "agent:     127.0.0.1:$LISTEN_PORT (persistent mTLS)"
echo

# 4. agents.toml for the CLI side.
AGENTS_CFG="$WORK/agents.toml"
cat > "$AGENTS_CFG" <<EOF
[agents.local]
address = "127.0.0.1:$LISTEN_PORT"
key_fingerprint = "sha256:$AGENT_FPR"
EOF
export PS_AGENTS_TOML="$AGENTS_CFG"

# 5. Local audit (sanity).
echo "--- local audit ssh ---"
LOCAL_OUT=$("$CLI" --jsonl audit ssh "127.0.0.1:$SSH_PORT")
echo "$LOCAL_OUT" | grep -q '"kind":"ssh.metadata"'    || { echo "FAIL: missing ssh.metadata (local)"; exit 1; }
echo "$LOCAL_OUT" | grep -q '"kind":"ssh.old_version"' || { echo "FAIL: missing ssh.old_version (local)"; exit 1; }
echo "$LOCAL_OUT" | sed 's/.*"title":"\([^"]*\)".*/    \1/' | sort -u
echo

# 6. Remote audit via the local agent.
echo "--- packetsonde --via local audit ssh ---"
REMOTE_OUT=$("$CLI" --jsonl --via local audit ssh "127.0.0.1:$SSH_PORT")
echo "$REMOTE_OUT" | grep -q '"kind":"ssh.metadata"'    || { echo "FAIL: missing ssh.metadata (--via)"; exit 1; }
echo "$REMOTE_OUT" | grep -q '"kind":"ssh.old_version"' || { echo "FAIL: missing ssh.old_version (--via)"; exit 1; }
echo "$REMOTE_OUT" | grep -q '"via_agent":"local"'      || { echo "FAIL: missing via_agent=local"; exit 1; }
echo "$REMOTE_OUT" | sed 's/.*"title":"\([^"]*\)".*/    \1/' | sort -u
echo

echo "=== self-test PASSED ==="
echo "agent log:"
sed 's/^/    /' "$WORK/agent.log"
