# Example pillar for the packetsonde agent salt state. Copy into your own pillar
# tree (e.g. pillar/roles/packetsonde.sls) and adjust. Real values are environment-
# specific and belong in YOUR private pillar — not in this repo.
#
# Assign to minions via your states top.sls (`- packetsonde`) and pillar top.sls
# (`- roles.packetsonde`). agent_id is the minion id.

packetsonde:
  central_url: "https://central.example:8700"   # your rna-packetsonde central; "" disables enroll
  deployment_mode: host                          # host | proxy | trunk | bridge
  verify: "1"                                    # "0" only for self-signed dev central
  ca_cert: ""                                    # optional internal CA pin
  checkin_seconds: "60"

  # Listener for audit-via / relay. persistent = always-on mTLS listener.
  agent_listen_mode: persistent                  # persistent | knock | both
  agent_listen_addr: "0.0.0.0"
  agent_listen_port: "8442"

# --- Per-node knock override (stealth: no idle listener) -------------------
# Put this in pillar/nodes/<minion-id>.sls and target that minion so it deep-
# merges over the defaults above. A signed broadcast knock opens an ephemeral
# session window (requires the passive discovery listener + CAP_NET_RAW).
#
#   packetsonde:
#     agent_listen_mode: knock
#     discovery_enabled: "1"
#     discovery_listen_ip: "198.51.100.10"       # this node's own address (example)
#     discovery_listen_port: "8442"
