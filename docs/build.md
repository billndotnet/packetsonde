# Building packetsonde

The CLI (`packetsonde`) and the agent (`packetsonded`) build from a
single CMake project. The build is portable across **macOS**, **Linux**,
and **FreeBSD / OPNsense**. There is one helper script — `build.sh` —
that wraps the underlying `cmake` invocations for the common case.

```bash
sudo ./bootstrap.sh  # install build deps (auto-detects platform)
./build.sh           # agent + cli
./build.sh agent     # agent only
./build.sh cli       # cli only
```

Binaries land in `build/src/cli/packetsonde` and `build/src/agent/packetsonded`.

The bootstrap dispatcher reads `/etc/os-release` and runs the right
per-platform installer from `packaging/bootstrap/`. Force a profile
with `PS_BOOTSTRAP_AS=ubuntu|redhat|freebsd ./bootstrap.sh` when the
detection misfires (derivative distros, custom builds, etc).

`PS_BUILD_DIR=/some/path ./build.sh` directs the build to an out-of-tree
location (CI, clean rebuilds, multiple targets in parallel).

---

## Build version

The build version (`X.Y.Z`, e.g. `0.1.1`) is what `packetsonde version`
and the `packetsonded` startup banner report. It is **separate** from the
`vN.N` milestone tags in `CHANGELOG.md` — those mark feature releases; the
build version identifies the binary.

**Single source of truth:** `set(PS_VERSION_STR "X.Y.Z")` at the top of the
root `CMakeLists.txt`. The root and agent `project()` calls both consume it,
and the CLI target gets it as `-DPS_VERSION` — so the CLI, agent, and
privilege-separated worker always report the same string. Do not edit the
version anywhere else.

**Dev-push policy:** bump the **patch (3rd) value** on every build you push
to the fleet. Binaries are deployed by hash (salt `file.managed`), so an
unchanged version string makes it impossible to confirm a host actually
took the new binary — bumping the patch makes the swap verifiable:

```
sudo salt '<host>' cmd.run '/usr/local/bin/packetsonde version'
```

should report the patch you just pushed. Reserve minor/major bumps for
feature milestones; routine dev/deploy builds only move the patch.

---

## macOS

Tested on Apple Silicon and Intel, macOS 12+. Apple ships libedit; the
rest comes from Homebrew.

```bash
brew install cmake openssl@3 libpcap hiredis pkg-config
./build.sh
```

OpenSSL location is autodetected via `find_package`. If Homebrew lives
somewhere unusual:

```bash
OPENSSL_ROOT_DIR=$(brew --prefix openssl@3) ./build.sh
```

### macOS install

```bash
sudo cmake --install build --prefix /usr/local
sudo mkdir -p /usr/local/etc/packetsonded/keys/authorized
sudo cp packaging/packetsonded.toml /usr/local/etc/packetsonded/
sudo packetsonde key generate --name agent
sudo cp packaging/net.billn.packetsonded.plist /Library/LaunchDaemons/
sudo launchctl bootstrap system /Library/LaunchDaemons/net.billn.packetsonded.plist
```

Alternative: `brew install --formula packaging/Formula/packetsonde.rb`
then `brew services start packetsonde`.

---

## Linux (Debian / Ubuntu)

Tested on Ubuntu 22.04 / 24.04 and Debian 12.

```bash
sudo apt update
sudo apt install -y \
    build-essential cmake pkg-config \
    libssl-dev libedit-dev libpcap-dev libhiredis-dev
./build.sh
```

### Linux install (systemd)

```bash
sudo cmake --install build              # equivalent: cd build && sudo make install
```

That places:

- `/usr/local/bin/packetsonde` — CLI
- `/usr/local/sbin/packetsonded` — agent
- `/usr/local/sbin/packetsonde-priv` — privilege-separated worker
- `/etc/packetsonded/packetsonded.toml.example` — annotated example config
- `/etc/packetsonded/keys/authorized/` — empty dir for authorized CLI pubkeys
- `/etc/systemd/system/packetsonded.service` — the unit file

The install step prints a 5-line "next steps" block. The condensed
version:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin packetsonded
sudo cp /etc/packetsonded/packetsonded.toml.example /etc/packetsonded/packetsonded.toml
sudo PS_KEY_DIR=/etc/packetsonded/keys packetsonde key generate --name agent
sudo cp ~/.config/packetsonde/keys/default.pub /etc/packetsonded/keys/authorized/
sudo systemctl daemon-reload && sudo systemctl enable --now packetsonded
```

The systemd unit grants `CAP_NET_RAW` + `CAP_NET_ADMIN` to the
unprivileged `packetsonded` user via ambient capabilities, then
sandboxes with `ProtectSystem=strict`, `NoNewPrivileges`,
`MemoryDenyWriteExecute`, etc. Review `packaging/packetsonded.service`
before deploying.

## Linux (RHEL / Fedora / Alma / Rocky)

```bash
sudo dnf install -y \
    gcc gcc-c++ cmake pkgconfig \
    openssl-devel libedit-devel libpcap-devel hiredis-devel
./build.sh
```

Install path is the same as Debian.

---

## FreeBSD

Tested on FreeBSD 14. libedit and libpcap are in base; only cmake,
openssl, and hiredis come from pkg. `bash` is required for `build.sh`
(the shell script uses `BASH_SOURCE`).

```bash
sudo pkg install -y bash cmake openssl pkgconf hiredis
./build.sh
```

If you prefer LibreSSL from base over the OpenSSL port:

```bash
OPENSSL_ROOT_DIR=/usr ./build.sh
```

### FreeBSD install (rc.d)

```bash
sudo cmake --install build --prefix /usr/local
sudo pw useradd packetsonded -d /nonexistent -s /usr/sbin/nologin
sudo mkdir -p /usr/local/etc/packetsonded/keys/authorized
sudo cp packaging/packetsonded.toml /usr/local/etc/packetsonded/
sudo -u packetsonded packetsonde key generate --name agent
sudo cp packaging/freebsd/packetsonded.rc /usr/local/etc/rc.d/packetsonded
sudo chmod +x /usr/local/etc/rc.d/packetsonded
sudo sysrc packetsonded_enable="YES"
sudo service packetsonded start
```

## OPNsense / pfSense

OPNsense is FreeBSD-based, so the FreeBSD instructions apply with a few
adjustments:

- Use the OPNsense **Shell** plugin (System → Settings → Administration)
  or SSH to get a root shell.
- `pkg` is restricted on OPNsense; install the build deps in a chroot
  or build the binaries on a sibling FreeBSD VM and `scp` them over.
  The binaries are statically linkable against musl/LibreSSL if you
  pass `-DBUILD_STATIC=ON` to cmake.
- The default `/usr/local/etc/rc.d/` is honored by OPNsense's rc system.
  After dropping the rc script, enable via:

  ```bash
  sysrc packetsonded_enable="YES"
  service packetsonded start
  ```

- OPNsense's firewall (`pf`) blocks inbound TCP by default; in
  **persistent** agent_listen mode you'll need to add a rule for the
  configured port (8442 by default). **knock** mode requires no firewall
  changes because no socket is bound between knocks.
- Passive capture: OPNsense already runs with appropriate privileges
  for libpcap on the WAN/LAN bridges; no extra capability config needed.

A useful OPNsense topology: a packetsonded next to the WAN bridge
running in `knock` mode, plus the CLI running on the auditor's laptop
inside the LAN. The auditor knocks → window opens → mTLS session →
agent audits the WAN-side perimeter from a vantage no internal scanner
can reach.

---

## Cross-compilation

Not currently supported by `build.sh`. For airgapped target deployment
the recommended pattern is "build on a matching VM, scp the binaries
and the runtime config." The agent has no dlopen requirements outside
the audit plugin loader (CLI-side), which can be disabled by not
providing a plugin directory.

## Build options

Pass any of these to `cmake` (or to `build.sh` via `PS_CMAKE_ARGS`):

| Option              | Default | Effect                                     |
|---------------------|---------|--------------------------------------------|
| `-DWITH_PCAP=OFF`   | ON      | Skip libpcap (disables passive modules)    |
| `-DWITH_REDIS=OFF`  | ON      | Skip hiredis (disables Redis bridge)       |
| `-DWITH_SSL=OFF`    | ON      | Skip OpenSSL (disables `audit tls`, mTLS)  |
| `-DBUILD_STATIC=ON` | OFF     | Statically link the agent binary           |
| `-DCMAKE_BUILD_TYPE=Release` | Debug | Optimized build                    |

## Verifying the build

```bash
cd build && ctest --output-on-failure
```

Should report 40/40 passing (as of v1.6). Integration tests requiring a
real network are marked SKIP on systems missing `python3`, and tests
needing root (raw sockets, pcap) are written to also work unprivileged
on most platforms.
