# Debian/Ubuntu Package Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `packetsonde` as a native Debian package so `sudo apt install ./packetsonde_<ver>_<arch>.deb` installs the CLI, agent, priv-worker, example config, and a *disabled* systemd unit on Ubuntu.

**Architecture:** A new top-level `debian/` directory drives `debhelper` with the cmake buildsystem (`dh $@ --buildsystem=cmake`), reusing the repo's existing CMake `install` rules. A new `PS_PACKAGED_BUILD` CMake option (default OFF) suppresses the two from-source-only install steps that conflict with Debian packaging. A `packaging/build-deb.sh` wrapper enforces package↔binary version lockstep and runs `dpkg-buildpackage`.

**Tech Stack:** CMake 3.20+, debhelper-compat 13, dpkg-dev, systemd, shell.

## Global Constraints

- **Single binary package** named `packetsonde` (CLI + agent + priv worker + unit). Format `3.0 (native)`.
- **Binary version = package version = `PS_VERSION_STR`** in root `CMakeLists.txt` (currently `0.1.4`). `build-deb.sh` MUST error if `debian/changelog`'s top version differs.
- **FHS prefix `/usr`**: `/usr/bin/packetsonde`, `/usr/sbin/packetsonded`, `/usr/sbin/packetsonde-priv`. Unit at `/lib/systemd/system/packetsonded.service`.
- **Unit ships disabled and stopped.** No key generation, no live config, no service start in maintainer scripts.
- **No Claude/Co-Authored-By footers in commits.** Use `git`/SSH only, never `gh`.
- Maintainer string: `Bill Nash <billn@billn.net>`.
- License: PolyForm Noncommercial 1.0.0 (modified) — see `LICENSE`.
- `from-source` `make install` behavior MUST remain byte-for-byte unchanged when `PS_PACKAGED_BUILD` is OFF (its default).

---

### Task 1: Gate from-source-only install steps behind `PS_PACKAGED_BUILD`

**Files:**
- Modify: `src/agent/CMakeLists.txt` (the systemd-unit install block ~446-453 and the `install(CODE …)` next-steps block ~462-484)

**Interfaces:**
- Produces: CMake cache option `PS_PACKAGED_BUILD` (BOOL, default `OFF`). When `ON`, the `/etc/systemd/system` unit install and the from-source `install(CODE)` next-steps message are skipped. All other install rules unchanged.

- [ ] **Step 1: Add the option near the other options.** In `src/agent/CMakeLists.txt`, immediately before the `include(GNUInstallDirs)` line (~418), add:

```cmake
# When packaging (deb/rpm), the package's maintainer scripts own systemd
# unit placement and the operator next-steps message. Skip the from-source
# versions so they don't conflict (e.g. a unit under /etc/systemd/system
# shadows the packaged /lib/systemd/system one). Default OFF preserves
# `make install` behavior exactly.
option(PS_PACKAGED_BUILD "Skip from-source-only install steps (deb/rpm packaging owns them)" OFF)
```

- [ ] **Step 2: Gate the systemd unit install.** Wrap the existing Linux unit-install block so it only runs for from-source builds:

```cmake
# systemd unit (Linux, from-source only). Installs to /etc/systemd/system
# regardless of prefix because that's where systemd reads unconditionally;
# from-source install at /usr/local/lib/systemd/system isn't picked up
# without an operator step. Package builds install the unit via
# dh_installsystemd instead (see debian/rules).
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT PS_PACKAGED_BUILD)
    install(FILES ${CMAKE_SOURCE_DIR}/packaging/packetsonded.service
            DESTINATION /etc/systemd/system)
endif()
```

- [ ] **Step 3: Gate the next-steps message.** Wrap the entire `install(CODE " … ")` block (the operator next-steps, ~462-484) in:

```cmake
if(NOT PS_PACKAGED_BUILD)
install(CODE "
... (leave the existing message body unchanged) ...
")
endif()
```

- [ ] **Step 4: Verify the option flips both behaviors.** From the repo root, configure twice into throwaway dirs and confirm the unit install is present off / absent on:

```bash
rm -rf /tmp/ps-off /tmp/ps-on
cmake -S . -B /tmp/ps-off >/dev/null 2>&1
cmake -S . -B /tmp/ps-on -DPS_PACKAGED_BUILD=ON >/dev/null 2>&1
grep -rl "etc/systemd/system" /tmp/ps-off/src/agent/cmake_install.cmake && echo "OFF: unit installed (correct)"
grep -rL "etc/systemd/system" /tmp/ps-on/src/agent/cmake_install.cmake >/dev/null && ! grep -q "etc/systemd/system" /tmp/ps-on/src/agent/cmake_install.cmake && echo "ON: unit NOT installed (correct)"
```

Expected: prints `OFF: unit installed (correct)` and `ON: unit NOT installed (correct)`.

- [ ] **Step 5: Commit.**

```bash
git add src/agent/CMakeLists.txt
git commit -m "build: add PS_PACKAGED_BUILD to skip from-source-only install steps"
```

---

### Task 2: Add the `debian/` packaging skeleton (control, changelog, copyright, format, rules)

**Files:**
- Create: `debian/control`
- Create: `debian/changelog`
- Create: `debian/copyright`
- Create: `debian/source/format`
- Create: `debian/rules` (mode 0755)

**Interfaces:**
- Consumes: `PS_PACKAGED_BUILD` from Task 1.
- Produces: a buildable source package. `debian/rules` defines `override_dh_auto_configure` (passes `-DPS_PACKAGED_BUILD=ON`), `override_dh_auto_test` (no-op), and `override_dh_installsystemd` (generates + installs the unit disabled). The generated unit basename is `packetsonded` (`--name=packetsonded`).

- [ ] **Step 1: Create `debian/source/format`.**

```
3.0 (native)
```

- [ ] **Step 2: Create `debian/control`.**

```
Source: packetsonde
Section: net
Priority: optional
Maintainer: Bill Nash <billn@billn.net>
Build-Depends:
 debhelper-compat (= 13),
 cmake,
 pkg-config,
 libssl-dev,
 libedit-dev,
 libpcap-dev,
 libhiredis-dev
Standards-Version: 4.6.2
Homepage: https://github.com/billndotnet/packetsonde
Rules-Requires-Root: no

Package: packetsonde
Architecture: any
Depends: ${shlibs:Depends}, ${misc:Depends}, adduser
Description: CLI-first network infrastructure and security auditing toolkit
 packetsonde is an auditor's command-line tool (active TLS/HTTP/DNS/SSH and
 20+ other service audits, port scans, traceroute) and packetsonded, a
 long-running passive observation agent (flow tracking, neighbour discovery,
 L2/L3 control-plane listeners, and host process/file/socket monitoring).
 .
 Findings are emitted as JSONL on stdout for piping to jq, vector, or any
 line-oriented log forwarder. The systemd service ships disabled; see
 /usr/share/doc/packetsonde for first-deployment steps.
```

- [ ] **Step 3: Create `debian/changelog`.** Version must equal `PS_VERSION_STR` (`0.1.4`):

```
packetsonde (0.1.4) unstable; urgency=medium

  * Initial Debian packaging: single native package shipping the CLI, the
    packetsonded agent, the privilege-separated worker, an example config,
    and a systemd unit (installed disabled).

 -- Bill Nash <billn@billn.net>  Fri, 26 Jun 2026 00:00:00 +0000
```

- [ ] **Step 4: Create `debian/copyright`** (machine-readable format 1.0):

```
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: packetsonde
Source: https://github.com/billndotnet/packetsonde

Files: *
Copyright: 2025-2026 Bill Nash <billn@billn.net>
License: PolyForm-Noncommercial-1.0.0-modified
 PolyForm Noncommercial License 1.0.0, modified to exclude government use.
 The full text is distributed in the source tree as LICENSE.
 The canonical (unmodified) text is at
 https://polyformproject.org/licenses/noncommercial/1.0.0
```

- [ ] **Step 5: Create `debian/rules`** (must be executable):

```make
#!/usr/bin/make -f

%:
	dh $@ --buildsystem=cmake

override_dh_auto_configure:
	dh_auto_configure -- -DPS_PACKAGED_BUILD=ON

override_dh_auto_test:
	# packetsonde's suite is real-infrastructure (live ES/Redis) and is
	# unsafe under the Release/NDEBUG flags dh uses (asserts stripped ->
	# spurious segfaults). Package builds skip it; ctest runs separately
	# on a Debug build in CI.

override_dh_installsystemd:
	# Generate the packaged unit from the canonical one, rewriting the
	# from-source ExecStart (/usr/local/sbin) to the FHS path (/usr/sbin).
	# Single checked-in unit file; no duplicate to drift.
	sed 's#/usr/local/sbin/packetsonded#/usr/sbin/packetsonded#' \
	    packaging/packetsonded.service > debian/packetsonded.service
	dh_installsystemd --name=packetsonded --no-enable --no-start
```

- [ ] **Step 6: Make `debian/rules` executable.**

```bash
chmod 0755 debian/rules
```

- [ ] **Step 7: Validate control/changelog parse.** On a host with dpkg-dev:

```bash
dpkg-parsechangelog -l debian/changelog | grep -E '^(Source|Version): '
```

Expected: `Source: packetsonde` and `Version: 0.1.4`.

- [ ] **Step 8: Commit.**

```bash
git add debian/control debian/changelog debian/copyright debian/source/format debian/rules
git commit -m "deb: add debhelper packaging skeleton (control, changelog, rules)"
```

---

### Task 3: Add maintainer scripts (service user + key-dir ownership)

**Files:**
- Create: `debian/packetsonde.postinst` (mode preserved by dpkg; no chmod needed)
- Create: `debian/packetsonde.postrm`

**Interfaces:**
- Consumes: `debian/rules`' `dh_installsystemd` (injects service start/stop/enable snippets at the `#DEBHELPER#` token).
- Produces: on `configure`, a system user+group `packetsonded`, and `/etc/packetsonded/keys` owned by it (mode 0750). On `purge`, the user is left in place (Debian convention for system users owning files).

- [ ] **Step 1: Create `debian/packetsonde.postinst`.**

```sh
#!/bin/sh
set -e

case "$1" in
    configure)
        # Unprivileged service account the systemd unit runs as.
        if ! getent passwd packetsonded >/dev/null; then
            adduser --system --no-create-home --group \
                    --shell /usr/sbin/nologin packetsonded
        fi
        # The key directory (created empty by cmake install) holds the
        # agent identity and authorized CLI pubkeys; the daemon reads it.
        if [ -d /etc/packetsonded/keys ]; then
            chown -R packetsonded:packetsonded /etc/packetsonded/keys
            chmod 0750 /etc/packetsonded/keys
        fi

        if [ -z "${2:-}" ]; then
            echo ""
            echo "=== packetsonde installed. The agent is NOT started. ==="
            echo "Next steps:"
            echo "  1. sudo cp /etc/packetsonded/packetsonded.toml.example \\"
            echo "             /etc/packetsonded/packetsonded.toml"
            echo "  2. sudo PS_KEY_DIR=/etc/packetsonded/keys \\"
            echo "          packetsonde key generate --name agent"
            echo "  3. sudo cp ~/.config/packetsonde/keys/default.pub \\"
            echo "             /etc/packetsonded/keys/authorized/"
            echo "  4. sudo systemctl enable --now packetsonded"
            echo ""
        fi
        ;;
esac

#DEBHELPER#

exit 0
```

- [ ] **Step 2: Create `debian/packetsonde.postrm`.** (No user removal; let dh handle the service. The explicit file keeps room for future purge cleanup and documents the deliberate choice.)

```sh
#!/bin/sh
set -e

# The packetsonded system user is intentionally left in place on purge:
# it may own files under /etc, /var/lib, or /var/log that survive removal.

#DEBHELPER#

exit 0
```

- [ ] **Step 3: Sanity-check the scripts are valid shell.**

```bash
sh -n debian/packetsonde.postinst && sh -n debian/packetsonde.postrm && echo "shell OK"
```

Expected: `shell OK`.

- [ ] **Step 4: Commit.**

```bash
git add debian/packetsonde.postinst debian/packetsonde.postrm
git commit -m "deb: maintainer scripts create packetsonded user, own key dir"
```

---

### Task 4: Add the `packaging/build-deb.sh` wrapper with version-lockstep guard

**Files:**
- Create: `packaging/build-deb.sh` (mode 0755)

**Interfaces:**
- Consumes: `PS_VERSION_STR` from root `CMakeLists.txt`; top version from `debian/changelog`.
- Produces: an executable wrapper that errors on version drift, else runs `dpkg-buildpackage -us -uc -b` and prints the `.deb` path.

- [ ] **Step 1: Create `packaging/build-deb.sh`.**

```bash
#!/usr/bin/env bash
# Build the packetsonde Debian package.
#
# Enforces that debian/changelog's top version matches PS_VERSION_STR in the
# root CMakeLists.txt -- the package version and the binary's reported version
# must always agree so a host's `packetsonde version` confirms which .deb it
# took (same verifiable-swap policy as the dev-push patch bump).
#
# Host build-deps: debhelper devscripts dpkg-dev  (plus the Build-Depends in
# debian/control, installed via `sudo apt build-dep .` or bootstrap-ubuntu.sh).
set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$REPO_ROOT"

# PS_VERSION_STR from the single source of truth.
CMAKE_VER="$(sed -n 's/^[[:space:]]*set(PS_VERSION_STR "\([0-9.]*\)").*/\1/p' CMakeLists.txt | head -1)"
# Top changelog version, e.g. "packetsonde (0.1.4) unstable; ..."
CHANGELOG_VER="$(sed -n 's/^packetsonde (\([0-9.]*\)).*/\1/p' debian/changelog | head -1)"

if [ -z "$CMAKE_VER" ]; then
    echo "ERROR: could not read PS_VERSION_STR from CMakeLists.txt" >&2
    exit 1
fi
if [ "$CMAKE_VER" != "$CHANGELOG_VER" ]; then
    echo "ERROR: version mismatch." >&2
    echo "  CMakeLists.txt PS_VERSION_STR = $CMAKE_VER" >&2
    echo "  debian/changelog top version  = $CHANGELOG_VER" >&2
    echo "Sync them before building, e.g.:" >&2
    echo "  dch -v $CMAKE_VER -D unstable 'Build $CMAKE_VER'" >&2
    exit 1
fi

echo "=== Building packetsonde $CMAKE_VER (.deb) ==="
dpkg-buildpackage -us -uc -b

DEB="$(ls -1t "$REPO_ROOT"/../packetsonde_"${CMAKE_VER}"_*.deb 2>/dev/null | head -1)"
echo ""
echo "=== Build complete ==="
if [ -n "$DEB" ]; then
    echo "Package: $DEB"
    echo "Install: sudo apt install \"$DEB\""
else
    echo "Package written to the parent directory ($REPO_ROOT/..)."
fi
```

- [ ] **Step 2: Make it executable.**

```bash
chmod 0755 packaging/build-deb.sh
```

- [ ] **Step 3: Verify the version-guard fires on drift and passes on match** (does not require deb tooling — exercises the guard before `dpkg-buildpackage`):

```bash
# Match case: extracts and compares cleanly.
bash -c 'sed -n "s/^[[:space:]]*set(PS_VERSION_STR \"\([0-9.]*\)\").*/\1/p" CMakeLists.txt | head -1'  # prints 0.1.4
sed -n 's/^packetsonde (\([0-9.]*\)).*/\1/p' debian/changelog | head -1                                  # prints 0.1.4
```

Expected: both print `0.1.4` (the guard's two inputs match, so it would proceed).

- [ ] **Step 4: Commit.**

```bash
git add packaging/build-deb.sh
git commit -m "deb: build-deb.sh wrapper with version-lockstep guard"
```

---

### Task 5: Document the package in build docs and packaging README

**Files:**
- Modify: `docs/build.md` (Linux Debian/Ubuntu section)
- Modify: `packaging/README.md` (file table)

**Interfaces:**
- Consumes: `packaging/build-deb.sh` (Task 4), the install layout (Tasks 1-3).
- Produces: operator-facing docs only.

- [ ] **Step 1: Add a "Debian package" subsection to `docs/build.md`** immediately after the "Linux install (systemd)" block:

````markdown
### Debian package (.deb)

Instead of `cmake --install` + manual systemd setup, build a native package:

```bash
sudo apt build-dep .          # or: sudo ./bootstrap.sh
sudo apt install -y debhelper devscripts dpkg-dev
packaging/build-deb.sh        # writes ../packetsonde_<ver>_<arch>.deb
sudo apt install ./../packetsonde_*.deb
```

The package installs binaries under `/usr` (`/usr/bin/packetsonde`,
`/usr/sbin/packetsonded`), the example config at
`/etc/packetsonded/packetsonded.toml.example`, and the systemd unit at
`/lib/systemd/system/packetsonded.service` **disabled**. It creates the
`packetsonded` system user. Then run the operator next-steps the postinst
prints (activate config, generate key, authorize a CLI pubkey,
`systemctl enable --now packetsonded`).

`build-deb.sh` refuses to build if `debian/changelog`'s version differs from
`PS_VERSION_STR` in `CMakeLists.txt`; bump both in lockstep (`dch -v <ver>`).
````

- [ ] **Step 2: Add the `debian/` artifacts to the table in `packaging/README.md`.** Append rows to the existing file table:

```
| `../debian/`                      | Linux    | Debian source package (debhelper) |
| `build-deb.sh`                    | Linux    | build the .deb (version-guarded)  |
```

- [ ] **Step 3: Verify the docs render and links are intact.**

```bash
grep -q "Debian package (.deb)" docs/build.md && grep -q "build-deb.sh" packaging/README.md && echo "docs OK"
```

Expected: `docs OK`.

- [ ] **Step 4: Commit.**

```bash
git add docs/build.md packaging/README.md
git commit -m "docs: document the Debian package build + install"
```

---

### Task 6: End-to-end acceptance on an Ubuntu host/chamber

**Files:** none (verification only).

**Interfaces:**
- Consumes: everything from Tasks 1-5.

This task has no code; it is the acceptance gate. Run on Ubuntu 22.04/24.04 (deb tooling: `dh`, `lintian`, `dch` are not on the primary dev host — use an Ubuntu chamber).

- [ ] **Step 1: Build the package.**

```bash
sudo apt build-dep . || sudo ./bootstrap.sh
sudo apt install -y debhelper devscripts dpkg-dev lintian
packaging/build-deb.sh
```

Expected: `../packetsonde_0.1.4_amd64.deb` produced.

- [ ] **Step 2: Lint (non-fatal advisory).**

```bash
lintian ../packetsonde_0.1.4_*.deb || true
```

Expected: no `E:` (error) tags. `W:`/`I:` are acceptable; note any for follow-up.

- [ ] **Step 3: Install and verify version + layout.**

```bash
sudo apt install -y ./../packetsonde_0.1.4_*.deb
packetsonde version                                   # -> 0.1.4
test -x /usr/sbin/packetsonded && test -x /usr/sbin/packetsonde-priv && echo "sbin OK"
test -f /etc/packetsonded/packetsonded.toml.example && echo "example config OK"
test ! -f /etc/packetsonded/packetsonded.toml && echo "no live config OK"
getent passwd packetsonded >/dev/null && echo "user OK"
```

Expected: `0.1.4`, then `sbin OK`, `example config OK`, `no live config OK`, `user OK`.

- [ ] **Step 4: Verify the unit is registered, disabled, and stopped.**

```bash
systemctl is-enabled packetsonded   # -> disabled
systemctl is-active packetsonded    # -> inactive
grep ExecStart /lib/systemd/system/packetsonded.service   # -> /usr/sbin/packetsonded
```

Expected: `disabled`, `inactive`, `ExecStart=/usr/sbin/packetsonded -c …`.

- [ ] **Step 5: Verify key-dir ownership.**

```bash
stat -c '%U:%G %a' /etc/packetsonded/keys   # -> packetsonded:packetsonded 750
```

- [ ] **Step 6: Exercise the operator path, confirm the agent runs.**

```bash
sudo cp /etc/packetsonded/packetsonded.toml.example /etc/packetsonded/packetsonded.toml
sudo PS_KEY_DIR=/etc/packetsonded/keys packetsonde key generate --name agent
sudo systemctl enable --now packetsonded
systemctl is-active packetsonded    # -> active
```

Expected: `active`. If it fails, `journalctl -u packetsonded -n50` per CLAUDE.md.

- [ ] **Step 7: Remove and purge.**

```bash
sudo apt remove -y packetsonde
systemctl is-enabled packetsonded 2>&1 | grep -q "No such file\|not-found\|masked" && echo "unit gone OK"
sudo apt purge -y packetsonde
test ! -f /etc/packetsonded/packetsonded.toml.example && echo "config purged OK"
getent passwd packetsonded >/dev/null && echo "user retained (expected)"
```

Expected: `unit gone OK`, `config purged OK`, `user retained (expected)`.

- [ ] **Step 8: Record results.** If all steps pass, the package is accepted. Note any `lintian` warnings worth a follow-up commit. No code commit in this task.

---

## Notes for the implementer

- The primary dev host has `dpkg-buildpackage` but **not** `dh`/`lintian`/`dch`. Tasks 1-5 are authoring + non-deb verification and can be done here; Task 6 must run on an Ubuntu chamber (see the lab-salt-infra / build-environments memory for spinning one up).
- Do not add a `module/` directory or touch ES mappings — out of scope.
- Keep commits free of Claude/Co-Authored-By footers (CLAUDE.md). Use SSH `git`, never `gh`.
