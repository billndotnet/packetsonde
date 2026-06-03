#!/bin/bash
# End-to-end process-collection validation. Requires root (fanotify).
# Verifies: a file read by a child process is attributed, via the ancestry
# walk, to a socket held by an ancestor (the SSH/EternalRed shape).
set -euo pipefail
cd "$(dirname "$0")/.."
AGENT=build/src/agent/packetsonde-agent
CLI=build/src/cli/packetsonde
SINK=/tmp/ps-activity-$$.jsonl
WATCH=/tmp/ps-watch-$$; mkdir -p "$WATCH"

[ "$(id -u)" = 0 ] || { echo "must run as root (fanotify needs CAP_SYS_ADMIN)"; exit 1; }

cat > /tmp/ps-detect-$$.toml <<EOF
[keys]
dir = "/tmp/ps-keys-$$"
[detect]
enabled       = "1"
watch_paths   = "$WATCH"
suppress_paths = "/usr/lib,/usr/share"
max_depth     = "16"
EOF
mkdir -p /tmp/ps-keys-$$

echo "Start the agent with the above config and PS detect sink -> $SINK, then:"
echo "  1. (terminal A) hold a socket + spawn a child that reads a watched file:"
echo "       python3 -c \"import socket,subprocess,time; s=socket.create_connection(('1.1.1.1',53)); subprocess.run(['cat','$WATCH/secret']); time.sleep(2)\" &"
echo "       echo data > $WATCH/secret"
echo "  2. (terminal B) tail records:"
echo "       $CLI watch --source $SINK --path secret"
echo
echo "PASS criteria: a record with path=$WATCH/secret, process.comm=cat (or python),"
echo "and a sockets[] entry owned by an ANCESTOR (depth>=1) with the held raddr —"
echo "i.e. the child's file read is attributed to the parent's socket."
echo
echo "Cleanup: rm -rf $SINK $WATCH /tmp/ps-detect-$$.toml /tmp/ps-keys-$$"
