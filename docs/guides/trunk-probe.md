# Trunk probe

## What this is

A `packetsonded` agent attached to a switch port configured as a dot1q trunk. The host sees traffic across many VLANs as 802.1Q-tagged frames, and can be configured with one virtual interface per VLAN. The agent can then audit, scan, or observe within each VLAN as though it were locally attached — useful for auditing segments behind ACLs you can't bypass from your laptop.

This is the "auditor with a small box plugged into a trunk port" model.

## When to use this

- You have legitimate access to a switch and can configure a trunk port.
- The auditor's laptop can't reach the segments you need to audit directly (firewalls, ACLs).
- You're doing a one-shot engagement and want a small physical or virtual host that can be removed when you're done.
- You want one observation point that sees multiple VLANs without moving cables.

Not the right shape if you want to be invisible on the wire — a trunk probe is an active host with an IP per VLAN. For passive observation, use the [bridge appliance](bridge-appliance.md) instead.

## Switch configuration

Configure the port the agent host is on as a trunk that carries the VLANs you want to see. Typical Cisco IOS:

```
interface GigabitEthernet1/0/24
 description packetsonde trunk
 switchport mode trunk
 switchport trunk encapsulation dot1q
 switchport trunk allowed vlan 10,20,30,40
 switchport nonegotiate
 spanning-tree portfast trunk
```

Allow only the VLANs you've been asked to audit. Adding others is scope creep on your part, not just a configuration convenience.

## Host configuration (Linux)

Bring up one subinterface per VLAN:

```bash
sudo ip link set dev eth0 up
sudo ip link add link eth0 name eth0.10 type vlan id 10
sudo ip link add link eth0 name eth0.20 type vlan id 20
sudo ip link add link eth0 name eth0.30 type vlan id 30
sudo ip link add link eth0 name eth0.40 type vlan id 40
sudo ip link set eth0.10 up
sudo ip link set eth0.20 up
sudo ip link set eth0.30 up
sudo ip link set eth0.40 up

# Get DHCP on each VLAN (or assign static IPs per scope agreement):
sudo dhclient eth0.10
sudo dhclient eth0.20
sudo dhclient eth0.30
sudo dhclient eth0.40
```

Verify visibility:

```bash
ip -br addr show | grep eth0
ping -c 2 -I eth0.10 10.10.0.1
```

## Running the agent

Install `packetsonded` on the host (build per the main README, then `make install` or copy the binary). Start it with capture on the relevant interfaces:

```bash
sudo packetsonded \
    --capture-iface eth0.10 \
    --capture-iface eth0.20 \
    --capture-iface eth0.30 \
    --capture-iface eth0.40 \
    --socket /var/run/packetsonde-agent.sock
```

(Or run via the systemd unit shipped under `src/agent/debian/`.)

## Running audits

Until the network agent protocol lands (`--via` follow-on), SSH to the trunk host and run the CLI locally there:

```bash
ssh trunkbox

# Discover hosts on each scoped VLAN
packetsonde discover hosts 10.10.0.0/24 --auto-append
packetsonde discover hosts 10.20.0.0/24 --auto-append
packetsonde discover hosts 10.30.0.0/24 --auto-append
packetsonde discover hosts 10.40.0.0/24 --auto-append

# Then audit anything interesting
packetsonde audit tls 10.20.0.42:443 --auto-append
packetsonde audit http https://10.30.0.10/ --auto-append
packetsonde audit ssh 10.30.0.10 --auto-append
```

When the network protocol ships, the same commands from the auditor's laptop:

```bash
packetsonde --via trunkbox discover hosts 10.10.0.0/24
packetsonde --via trunkbox audit tls 10.20.0.42:443
```

`via_agent` will appear on every emitted finding so the auditor's collated JSONL clearly attributes which agent observed which thing.

## Collecting findings

The agent writes its own observations to its IPC socket; the CLI emits its audits to stdout (and, with `--auto-append`, to a dated JSONL file in `$XDG_STATE_HOME/packetsonde/`).

Recommended end-of-engagement collection:

```bash
ssh trunkbox tar -czf - ~/.local/state/packetsonde/ > engagement-trunkbox-$(date -u +%Y%m%d).tar.gz
```

## Tear-down

```bash
sudo systemctl stop packetsonded
sudo ip link delete eth0.10
sudo ip link delete eth0.20
sudo ip link delete eth0.30
sudo ip link delete eth0.40
```

Have the switch port returned to its previous configuration. Keep a copy of the engagement's findings tarball and the agent's logs.

## What you'll see

A trunk probe is most valuable for the verbs that benefit from privileged network position: `discover hosts`, `discover neighbors`, `scan ports`, and any `audit` against services that aren't reachable from outside the segment. TLS / HTTP / SSH audits look the same as they would from anywhere — the value is *being able to reach the target*.
