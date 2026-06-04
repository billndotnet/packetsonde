#!/bin/bash
# Assisted live test for the learned per-exe baseline. Requires root + a service.
set -euo pipefail
cd "$(dirname "$0")/.."
[ "$(id -u)" = 0 ] || { echo "must run as root (fanotify)"; exit 1; }
echo "Steps:"
echo "  1. Run the agent with [detect] enabled=1, watch_paths covering the target's dirs,"
echo "     baseline_mode=on (policy_mode may also be on — the ring fan-out feeds both),"
echo "     baseline_state_dir=/var/lib/packetsonde/baseline."
echo "  2. Exercise the target binary through NOMINAL flows. Candidate findings"
echo "     (channel baseline.candidate) appear for each new path; the agent appends them."
echo "  3. Bulk-approve the nominal set:"
echo "       ./build/src/cli/packetsonde baseline <exe-path> approve-all"
echo "  4. Trigger an ABNORMAL access by that exe (a path it never touches), then deny it:"
echo "       ./build/src/cli/packetsonde baseline <exe-path> deny <path>"
echo
echo "PASS: after approve-all, nominal paths stop producing candidates; the denied path"
echo "      produces a baseline.anomaly (severity high) finding on each sighting."
echo
echo "Network destinations (Phase B):"
echo "  - With baseline_mode=on, an exe connecting to a NEW raddr yields a baseline.candidate"
echo "    (signal=dest). Approve it (optionally generalized):"
echo "       ./build/src/cli/packetsonde baseline <exe-path> approve-dest <ip:port> --as cidr/24"
echo "  - A connection to a denied host yields a baseline.anomaly (signal=dest):"
echo "       ./build/src/cli/packetsonde baseline <exe-path> deny-dest <ip:port>"
echo "Cleanup: rm -rf /var/lib/packetsonde/baseline/<slug>"
