#!/bin/bash
# Assisted live test for sandbox learning. Requires root + systemd.
# Runs a service under policy_mode=learn, then synthesizes its sandbox stanza.
set -euo pipefail
cd "$(dirname "$0")/.."
[ "$(id -u)" = 0 ] || { echo "must run as root (fanotify)"; exit 1; }
echo "Steps:"
echo "  1. Run the agent with [detect] enabled=1, watch_paths covering the service's"
echo "     data dirs (e.g. /etc,/var,/run,/tmp), policy_mode=learn,"
echo "     learn_state_dir=/var/lib/packetsonde/sandbox-learn."
echo "  2. Exercise the target service through its NOMINAL flows for a while"
echo "     (start it, hit its endpoints, let it write its data/logs)."
echo "  3. Wait ~10s for a flush, then:"
echo "       ./build/src/cli/packetsonde sandbox-suggest <unit>.service"
echo
echo "PASS: a [Service] stanza whose ReadWritePaths cover exactly the dirs the"
echo "      service wrote, ProtectHome=true if it never touched /home, MDWE=yes if"
echo "      it never execed from a writable path. Sanity-check, then optionally apply"
echo "      it as a drop-in and switch to policy_mode=overwatch to verify enforcement."
echo "Cleanup: rm -f /var/lib/packetsonde/sandbox-learn/<unit>.service.json"
