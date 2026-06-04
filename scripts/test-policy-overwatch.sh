#!/bin/bash
# Assisted live test for systemd policy overwatch. Requires root + systemd.
# Verifies an enforcement-gap finding: a unit declares ProtectHome=true but its
# process reads /home, and overwatch flags it.
set -euo pipefail
cd "$(dirname "$0")/.."
[ "$(id -u)" = 0 ] || { echo "must run as root (fanotify + systemctl)"; exit 1; }
SINK=/tmp/ps-act-$$.jsonl

echo "Setup:"
echo "  1. Pick or create a test unit with: [Service] ProtectHome=true ReadWritePaths=/var/lib/testapp"
echo "     (do NOT restart it after editing if you want to observe the *gap*; or use a unit whose"
echo "      ProtectHome is declared but the running process predates the setting)."
echo "  2. Run the agent with [detect] enabled=1, watch_paths includes /home, policy_mode=overwatch,"
echo "     activity sink -> $SINK."
echo "  3. As the unit's user/process, read a file under /home."
echo
echo "PASS: a published finding (channel policy.sandbox.violation) with"
echo "      unit=<unit>, directive=ProtectHome, path=/home/..., op=open|read, severity=high."
echo "      Check the agent's finding output / central ps_events."
echo
echo "Also exercise: write outside ReadWritePaths under ProtectSystem=strict -> directive=ProtectSystem."
echo "Cleanup: revert the unit edit; rm -f $SINK"
