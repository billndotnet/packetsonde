# Packaging

Per-platform deployment artifacts for `packetsonded`.

| File                              | Platform | Purpose                          |
|-----------------------------------|----------|----------------------------------|
| `packetsonded.toml`               | all      | example agent config             |
| `packetsonded.service`            | Linux    | systemd unit (user `packetsonded`)|
| `kernelsonded.service`            | Linux    | systemd unit (user `kernelsonded`)|
| `kernelsonded.toml`               | Linux    | example kernelsonded config       |
| `net.billn.packetsonded.plist`    | macOS    | launchd plist (root-owned)       |
| `Formula/packetsonde.rb`          | macOS    | Homebrew formula                 |
| `../debian/`                      | Linux    | Debian source package (debhelper) |
| `build-deb.sh`                    | Linux    | build the .deb (version-guarded)  |

## First-time deployment

1. **Install the binaries.** Either build from source (`./build.sh native`) or, on macOS, `brew install --formula packaging/Formula/packetsonde.rb`.
2. **Generate the agent identity:**
    ```bash
    sudo packetsonde key generate --name agent
    ```
3. **Drop the example config into place** at `/etc/packetsonded/packetsonded.toml` (Linux) or `/usr/local/etc/packetsonded/packetsonded.toml` (macOS / Homebrew).
4. **Authorize the CLI's pubkey:**
    ```bash
    sudo mkdir -p /etc/packetsonded/keys/authorized
    sudo cp ~/.config/packetsonde/keys/default.pub /etc/packetsonded/keys/authorized/cli.pub
    ```
5. **Start the daemon:**
    - Linux: `sudo systemctl enable --now packetsonded`
    - macOS: `sudo launchctl bootstrap system /Library/LaunchDaemons/net.billn.packetsonded.plist`
    - Homebrew: `brew services start packetsonde`

## Configuration

The agent reads `-c /path/to/packetsonded.toml`. Section keys are translated to env vars (`config_to_env.c`) and consumed by the modules. Pre-existing `PS_*` env vars override file values, so launch-time overrides are clean:

```ini
# systemd drop-in to override the export collector:
[Service]
Environment=PS_NETFLOW_COLLECTOR=collector.internal:2055
```

## Capability requirements

- **libpcap** — Linux: `CAP_NET_RAW` + `CAP_NET_ADMIN` granted by the systemd unit. macOS: BPF requires root or `access_bpf` group.
- **NetFlow / IPFIX export** — outbound UDP only; no special capabilities.
- **mTLS listener** (port 8442 default) — no special capabilities.
- **knock mode** — pcap-only path; no listening socket; no privileges beyond pcap.
