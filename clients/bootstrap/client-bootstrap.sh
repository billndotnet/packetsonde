#!/usr/bin/env bash
# client-bootstrap.sh -- provision an mTLS client identity for the LOCAL
# packetsonde agent (Linux / macOS / SteamOS).
#
# It:
#   1. ensures the agent has an identity key,
#   2. generates a client keypair (the UI/psctl identity),
#   3. authorizes the client with the agent (drops its pubkey in authorized/),
#   4. prints the agent fingerprint to pin + a ready-to-run connect command,
#   5. tells you exactly how to (re)launch the agent with mTLS TCP enabled.
#
# Idempotent: existing keys are reused, re-authorized. Safe to re-run.
#
# Usage:
#   ./client-bootstrap.sh [--name NAME] [--listen ADDR:PORT] [--launch]
# Env overrides:
#   PS_KEY_DIR     agent keystore dir   (default: $HOME/.config/packetsonde/keys)
#   PACKETSONDE    path to the CLI      (default: PATH, else ../../build/src/cli/packetsonde)
set -euo pipefail

NAME="ui"
LISTEN="127.0.0.1:4701"   # loopback by default; use 0.0.0.0:PORT for LAN access
LAUNCH=0
AUTHORIZE_PUB=""   # authorize an EXISTING pubkey (e.g. a UE UI identity) instead of generating one
while [ $# -gt 0 ]; do
  case "$1" in
    --name)      NAME="$2"; shift 2 ;;
    --listen)    LISTEN="$2"; shift 2 ;;
    --launch)    LAUNCH=1; shift ;;
    --authorize) AUTHORIZE_PUB="$2"; shift 2 ;;   # path to an existing <id>.pub to authorize
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# --- locate the packetsonde CLI -------------------------------------------
here="$(cd "$(dirname "$0")" && pwd)"
PACKETSONDE="${PACKETSONDE:-}"
if [ -z "$PACKETSONDE" ]; then
  if command -v packetsonde >/dev/null 2>&1; then
    PACKETSONDE="$(command -v packetsonde)"
  elif [ -x "$here/../../build/src/cli/packetsonde" ]; then
    PACKETSONDE="$here/../../build/src/cli/packetsonde"
  else
    echo "error: packetsonde CLI not found. Install it or set PACKETSONDE=/path/to/packetsonde" >&2
    exit 1
  fi
fi

KEYDIR="${PS_KEY_DIR:-$HOME/.config/packetsonde/keys}"
export PS_KEY_DIR="$KEYDIR"
mkdir -p "$KEYDIR/authorized"
chmod 700 "$KEYDIR" 2>/dev/null || true

echo "==> keystore: $KEYDIR"
echo "==> cli:      $PACKETSONDE"

# --- 1. agent identity -----------------------------------------------------
if [ ! -f "$KEYDIR/agent.sec" ]; then
  echo "==> generating agent identity"
  "$PACKETSONDE" key generate --name agent >/dev/null
fi

# --- 2. client identity ----------------------------------------------------
# Either authorize an existing pubkey (--authorize, e.g. a UE UI's
# Saved/agent-id/agent.pub) or generate a standalone client key here.
if [ -n "$AUTHORIZE_PUB" ]; then
  [ -f "$AUTHORIZE_PUB" ] || { echo "error: --authorize pubkey not found: $AUTHORIZE_PUB" >&2; exit 1; }
  client_pub="$AUTHORIZE_PUB"
  client_sec="${AUTHORIZE_PUB%.pub}.sec"   # sibling seed (lives with the UE identity)
else
  if [ ! -f "$KEYDIR/$NAME.sec" ]; then
    echo "==> generating client identity '$NAME'"
    "$PACKETSONDE" key generate --name "$NAME" >/dev/null
  else
    echo "==> reusing existing client identity '$NAME'"
  fi
  client_pub="$KEYDIR/$NAME.pub"
  client_sec="$KEYDIR/$NAME.sec"
fi

# --- 3. authorize the client with the agent --------------------------------
cp -f "$client_pub" "$KEYDIR/authorized/$NAME.pub"
echo "==> authorized $(basename "$client_pub") as $NAME.pub in $KEYDIR/authorized/"

# --- 4. fingerprints -------------------------------------------------------
agent_fpr="$("$PACKETSONDE" key fingerprint agent       | grep -oE 'sha256:[0-9a-f]+' | head -1)"
client_fpr="$("$PACKETSONDE" key fingerprint "$client_pub" | grep -oE 'sha256:[0-9a-f]+' | head -1)"

host="${LISTEN%:*}"; port="${LISTEN##*:}"
psctl="$here/../go/psctl/psctl"
[ -x "$psctl" ] || psctl="psctl"

cat <<EOF

================ client bootstrap complete ================
client key   : $client_sec   (keep private)
client fpr   : $client_fpr
agent  fpr   : $agent_fpr   <-- pin this from the client

Run the agent with mTLS TCP enabled:
  PS_KEY_DIR="$KEYDIR" PS_NETWORK_LISTEN="$LISTEN" PS_NETWORK_TLS=1 packetsonded
or in packetsonded.toml:
  [network]
  listen = "$LISTEN"
  tls    = "1"

Connect with psctl:
  $psctl --host $host --port $port --key "$client_sec" --agent-fpr $agent_fpr hosts

Or, for a UE UI using this identity, launch the editor with:
  PS_AGENT_TCP=$host:$port
  PS_AGENT_FINGERPRINT=$agent_fpr
===========================================================
EOF

# --- 5. optional: launch the agent in the foreground for a quick try -------
if [ "$LAUNCH" = "1" ]; then
  echo "==> launching agent (PS_NETWORK_TLS=1 on $LISTEN); Ctrl-C to stop"
  exec env PS_KEY_DIR="$KEYDIR" PS_NETWORK_LISTEN="$LISTEN" PS_NETWORK_TLS=1 \
       "$(dirname "$PACKETSONDE")/../agent/packetsonded"
fi
