#!/bin/bash
# inspect --stream over a fixture sink: emits a profile.v1 keyframe with entities.
set -e
BUILD_DIR="${PS_BUILD_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/build}"
CLI="$BUILD_DIR/src/cli/packetsonde"
[ -x "$CLI" ] || { echo "skip: no CLI"; exit 77; }
W=$(mktemp -d); trap "rm -rf $W" EXIT
SINK="$W/activity.jsonl"
cat > "$SINK" <<'EOF'
{"v":1,"ts":"2026-06-05T19:00:00Z","event":"open","path":"/etc/shadow","partial":false,"process":{"pid":4242,"ppid":900,"uid":0,"sid":900,"comm":"x","exe":"/usr/bin/x","cmdline":"x","cgroup":"/system.slice/sshd","mac":{"label":"unconfined","mode":"enforcing"}},"ancestry":[{"pid":1,"comm":"systemd","depth":1}],"sockets":[]}
{"v":1,"ts":"2026-06-05T19:00:01Z","event":"connect","path":"","partial":false,"process":{"pid":4242,"ppid":900,"uid":0,"sid":900,"comm":"x","exe":"/usr/bin/x","cmdline":"x","cgroup":"/system.slice/sshd","mac":{"label":"unconfined","mode":"enforcing"}},"ancestry":[],"sockets":[{"owner_pid":4242,"owner_comm":"x","depth":0,"proto":"tcp","laddr":"10.0.0.5:5","raddr":"10.0.0.9:443","state":"ESTAB"}]}
EOF
OUT=$(PS_DETECT_BASELINE_DIR="$W/none" "$CLI" inspect --exe /usr/bin/x --source "$SINK" --stream --once 2>&1)
echo "$OUT"
echo "$OUT" | grep -q '"type":"keyframe"' || { echo "FAIL: no keyframe"; exit 1; }
echo "$OUT" | grep -q '"id":"file:/etc/shadow"' || { echo "FAIL: missing file entity"; exit 1; }
echo "$OUT" | grep -q '"id":"dest:10.0.0.9:443"' || { echo "FAIL: missing dest entity"; exit 1; }
echo "test_inspect_stream: OK"
