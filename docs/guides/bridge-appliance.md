# Passive bridge appliance

## What this is

A small portable host (Raspberry Pi 4/5, Mini-PC, or similar) configured as a transparent Ethernet bridge between two network segments. Two NICs join the bridge, packets forward at layer 2 without modification, and `packetsonded` observes everything that crosses. A third interface (typically wifi) is the auditor's management connection — they SSH or connect a CLI to it without touching the production network at all.

The result: a tap-style observation point that requires no switch config, no SPAN port, and no agent address on the inspected segments. The bridge has no IP on the inspected side, so it's invisible to L3 scanning.

## When to use this

- You're auditing a network you don't administer and can't configure mirroring on.
- You need to observe traffic between two specific points (e.g., between a server and an upstream router).
- You're doing physical engagements where dropping a small device between a host and its switch is operationally simpler than configuring SPAN.
- You want flow records, neighbor-table contents, DHCP/DNS/LLDP/CDP observations from a position the network treats as a length of cable.

Not the right shape if you need to actively probe segments — the bridge has no L3 presence on the data plane, so the CLI's active verbs (`scan ports`, `audit tls`) can't reach anything from it. Pair with a [trunk probe](trunk-probe.md) for that, or run the active CLI from the management interface (wifi-attached auditor laptop) against the inspected segment via the bridged host's L2 forwarding.

## Hardware

Minimum:
- Two wired Ethernet NICs (e.g., USB-Ethernet adapters on a Pi 4, or onboard + USB on a Pi 5).
- One wifi interface (onboard wifi is fine; an external USB wifi adapter with AP mode capability is better).
- Enough storage for the engagement's pcaps and findings — at least 64 GB SD/SSD.
- Power. UPS-buffered preferred for stability during an engagement.

Tested-clean shape: Raspberry Pi 5 with a USB3 GbE adapter as the second wired NIC and onboard wifi as the management interface.

## Bridge configuration (Linux)

The principle is: create a Linux bridge that owns both wired NICs, do *not* assign it an IP on the inspected segments, enable promiscuous mode, and have `packetsonded` capture from the bridge interface itself.

```bash
# Stop NetworkManager from "helping"
sudo systemctl stop NetworkManager  # or write a connection profile that ignores eth0/eth1

# Build the bridge
sudo ip link add name br0 type bridge
sudo ip link set br0 up
sudo ip link set eth0 master br0
sudo ip link set eth1 master br0
sudo ip link set eth0 promisc on up
sudo ip link set eth1 promisc on up

# Disable the bridge's MAC-learning aging if you want every packet visible
# (default behavior is fine for most audits; only enable this if you need it):
# sudo ip link set br0 type bridge ageing_time 0

# Verify
ip -br link show
```

You should see `eth0` and `eth1` both bound to `br0`, all three UP, with `eth0` and `eth1` carrying `promisc`. The bridge has no IP — that's deliberate.

Make it persist (Debian/Ubuntu, `/etc/systemd/network/10-br0.netdev`):

```ini
[NetDev]
Name=br0
Kind=bridge
```

And `20-br0.network`:

```ini
[Match]
Name=br0

[Network]
# No DHCP, no static IP — bridge is L2-only on the data plane
LinkLocalAddressing=no
IPv6AcceptRA=no
```

Plus `10-eth0.network` and `10-eth1.network` to bind those interfaces to the bridge.

## Wifi management plane

Run the wifi as an access point so the auditor can connect directly. Sample `hostapd` config (`/etc/hostapd/hostapd.conf`):

```
interface=wlan0
ssid=packetsonde-mgmt
hw_mode=g
channel=6
auth_algs=1
wpa=2
wpa_passphrase=USE-A-LONG-RANDOM-PASSPHRASE
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_pairwise=CCMP
```

Run dhcpd on wlan0 with a /29 or /30 so only the auditor's laptop joins. SSH on the bridge host listens on wlan0 only:

```bash
# /etc/ssh/sshd_config.d/packetsonde.conf
ListenAddress 192.168.99.1
```

The data-plane bridge and the management plane are completely isolated: no routing between them, no IP on the data side, all traffic terminates at the agent process.

## Running the agent

```bash
sudo packetsonded \
    --capture-iface br0 \
    --socket /var/run/packetsonde-agent.sock \
    --flow-export /var/log/packetsonde/flows.jsonl
```

The agent reads from the bridge interface in promiscuous mode (everything that crosses), generates flow records, and runs its passive listeners (DHCP, DNS, LLDP, CDP, STP, neighbor discovery, etc.). Its findings stream to its IPC socket and, configured, to a JSONL file.

## Auditor workflow

```bash
# Connect to the bridge's wifi
# (laptop joins SSID "packetsonde-mgmt")

# SSH to the bridge
ssh pi@192.168.99.1

# Watch live events
packetsonde agent listen

# Look at discovered hosts (agent has been observing passively)
packetsonde agent hosts

# Detailed view of one
packetsonde agent host 10.0.0.42

# Pull the day's flow file off the box
exit
scp pi@192.168.99.1:/var/log/packetsonde/flows.jsonl ./
```

For active auditing from this position — e.g. an `audit tls` against something the bridge can see on the inspected segment — the bridge itself can't initiate (no L3 presence on the data plane). The two options are:

1. **From the auditor's laptop**, with a temporary IP added to the laptop's wifi NIC that's *also* on the inspected segment (only works if the bridge's two ports are on the same L2 broadcast domain and the engagement allows it).
2. **Add a temporary IP to the bridge for the duration of the active probe**, run the probe, remove the IP. This makes the bridge briefly visible at L3, which is operationally what you want during an audit but undoes the invisibility property; do it only with engagement approval.

```bash
# Temporary L3 presence on the inspected segment
sudo ip addr add 10.0.0.99/24 dev br0
packetsonde audit tls 10.0.0.42:443
sudo ip addr del 10.0.0.99/24 dev br0
```

## End-of-engagement

```bash
# Stop capturing
sudo systemctl stop packetsonded

# Bundle findings + flows + the bridge's MAC/host table
ssh pi@192.168.99.1 sudo tar -czf - \
    /var/log/packetsonde/ \
    /var/lib/packetsonde/ \
    /etc/packetsonde/ > engagement-bridge-$(date -u +%Y%m%d).tar.gz

# Disassemble the bridge
sudo ip link set eth0 nomaster
sudo ip link set eth1 nomaster
sudo ip link delete br0
```

## Operational gotchas

- **Bridge ageing.** Linux bridges learn MAC addresses by default. For *audit* purposes that's usually fine — the captured frames still hit the agent. If you need every packet visible (some research workflows), `ip link set br0 type bridge ageing_time 0` disables aging.
- **STP.** A bridge with STP enabled can briefly take down a port while it negotiates spanning tree. Set `stp_state=0` if the segment is sensitive to that.
- **Promiscuous mode.** Required on both wired NICs for the agent to see everything. If your distro / NetworkManager keeps disabling it, configure that out.
- **Wifi country code.** On a Pi, `sudo raspi-config` → Localisation → set WLAN country, or your wifi may refuse to come up.
- **Physical security.** A handheld device with promiscuous capture is a juicy target for whoever owns the network. Don't leave it unattended overnight. At minimum, encrypt the storage and bind SSH to the wifi NIC only with key auth.
