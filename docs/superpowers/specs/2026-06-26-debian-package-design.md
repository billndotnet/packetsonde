# Debian/Ubuntu package for packetsonde — design

**Date:** 2026-06-26
**Status:** Approved, pending implementation plan

## Goal

Ship `packetsonde` as a native Debian package so a fresh Ubuntu host can go
from nothing to "installed, configured, ready for the operator to enable"
with a single `apt install ./packetsonde_<ver>_<arch>.deb`. This replaces the
~7 hand-typed commands currently documented in `docs/build.md` (useradd →
config copy → key generate → authorize pubkey → `systemctl enable --now`).

Non-goals: a published apt repository, signed packages, `.deb` for non-amd64
beyond what `dpkg-buildpackage` produces natively, or RPM/other distros.

## Package shape

- **Single binary package: `packetsonde`** — ships the CLI, the agent, the
  privilege-separated worker, the example config, and a systemd unit.
- **Native package** (`3.0 (native)`): packaging lives in this repo alongside
  the source; there is no separate upstream tarball.
- **Architecture: `any`**. Built with **debhelper using the cmake
  buildsystem** (`dh $@ --buildsystem=cmake`). dh drives our existing CMake
  install rules into `debian/packetsonde/` via `DESTDIR`, so we do not
  hand-maintain a `.install` file.

### Installed layout (prefix `/usr`, set by dh)

| Path | Source |
|---|---|
| `/usr/bin/packetsonde` | CLI (`src/cli` install rule) |
| `/usr/sbin/packetsonded` | agent (`src/agent` install rule) |
| `/usr/sbin/packetsonde-priv` | priv worker (`src/agent` install rule) |
| `/etc/packetsonded/packetsonded.toml.example` | example config |
| `/etc/packetsonded/keys/authorized/` | empty dir for authorized CLI pubkeys |
| `/lib/systemd/system/packetsonded.service` | unit (installed by `dh_installsystemd`) |

The live `/etc/packetsonded/packetsonded.toml` is **not** shipped — the
operator copies it from `.toml.example`. Only the `.example` is a dpkg
conffile.

## Files added (new top-level `debian/`)

- `debian/control`
  - `Source: packetsonde`, `Section: net`, `Priority: optional`,
    `Maintainer: Bill Nash <billn@billn.net>`.
  - `Build-Depends:` mirrors `packaging/bootstrap/bootstrap-ubuntu.sh` build
    set — `debhelper-compat (= 13)`, `build-essential`, `cmake`,
    `pkg-config`, `libssl-dev`, `libedit-dev`, `libpcap-dev`,
    `libhiredis-dev`.
  - `Package: packetsonde`, `Architecture: any`,
    `Depends: ${shlibs:Depends}, ${misc:Depends}, adduser`.
  - `Description:` short + extended, matching the README one-liner.
- `debian/changelog` — native package versions; top entry must equal
  `PS_VERSION_STR`. Initial entry `0.1.4` (current `CMakeLists.txt` value).
- `debian/copyright` — derived from `LICENSE`.
- `debian/rules` — see below.
- `debian/source/format` — `3.0 (native)`.
- `debian/packetsonde.postinst` — creates the service user and fixes key-dir
  ownership; `#DEBHELPER#` token carries dh's service snippets. Prints the
  next-steps block.
- `debian/packetsonde.prerm` / `debian/packetsonde.postrm` — dh-generated
  service stop/cleanup; the `packetsonded` user is **left in place on purge**
  (Debian convention for system users that may own files).

## debian/rules behavior

```make
#!/usr/bin/make -f
%:
	dh $@ --buildsystem=cmake

override_dh_auto_configure:
	dh_auto_configure -- -DPS_PACKAGED_BUILD=ON

override_dh_auto_test:
	# packetsonde's suite needs live ES/Redis and is unsafe under the
	# Release/NDEBUG flags dh uses (asserts stripped → spurious segfaults).
	# Package builds skip it; CI runs ctest separately on a Debug build.

override_dh_installsystemd:
	# Generate the packaged unit from the canonical one, fixing ExecStart
	# to the FHS sbin path, then install it disabled + stopped.
	sed 's#/usr/local/sbin/packetsonded#/usr/sbin/packetsonded#' \
	    packaging/packetsonded.service > debian/packetsonded.service
	dh_installsystemd --no-enable --no-start --name=packetsonded
```

- **Unit ships disabled and stopped** (`--no-enable --no-start`): a network
  capture daemon must not start unattended. No key generation, no live
  config at install time.
- **ExecStart path:** the canonical `packaging/packetsonded.service` points at
  `/usr/local/sbin/packetsonded` (from-source default). `debian/rules`
  `sed`-rewrites it to `/usr/sbin/packetsonded` at build time, keeping a
  single checked-in unit file (no duplicate to drift).

## postinst contents (sketch)

```sh
case "$1" in
  configure)
    adduser --system --no-create-home --group \
            --shell /usr/sbin/nologin packetsonded || true
    # cmake created /etc/packetsonded/keys/authorized; tighten ownership
    chown -R packetsonded:packetsonded /etc/packetsonded/keys || true
    chmod 0750 /etc/packetsonded/keys ;;
esac
#DEBHELPER#
```

Followed by an echoed 5-step next-steps block (reuse the wording already in
the CMake `install(CODE …)`): activate config, generate the agent key,
authorize a CLI pubkey, `systemctl enable --now packetsonded`.

## Changes to existing files

### `src/agent/CMakeLists.txt`

Add a CMake option, default OFF so from-source `make install` is unchanged:

```cmake
option(PS_PACKAGED_BUILD "Skip from-source-only install steps (deb/rpm packaging owns them)" OFF)
```

When `PS_PACKAGED_BUILD` is `ON`:
- **Skip** the `install(FILES … packetsonded.service DESTINATION
  /etc/systemd/system)` rule (lines ~450–453). The package installs the unit
  to `/lib/systemd/system` via `dh_installsystemd` instead, and a unit under
  `/etc/systemd/system` would shadow it.
- **Skip** the from-source `install(CODE …)` next-steps message (lines
  ~462+). The deb's postinst prints next-steps.

All other install rules (binaries, config, key dir) run unchanged under the
dh-provided prefix.

## Build wrapper: `packaging/build-deb.sh`

- Reads `PS_VERSION_STR` from the root `CMakeLists.txt` and the top version
  from `debian/changelog`. If they differ, **error** with guidance:
  `run: dch -v <PS_VERSION_STR> -D unstable` — enforcing the same
  verifiable-swap version lockstep the dev-push policy requires (binary
  version and package version always agree).
- On match, runs `dpkg-buildpackage -us -uc -b` (binary-only, unsigned) and
  prints the resulting `.deb` path (parent dir per dpkg convention).
- Documents its own host build-deps in a header comment: `debhelper`,
  `devscripts`, `dpkg-dev` (plus the `Build-Depends` set, installed by
  `bootstrap-ubuntu.sh` or `apt build-dep .`).

## Documentation

- `docs/build.md`: add a "Debian package" subsection under Linux — build with
  `packaging/build-deb.sh`, install with `sudo apt install ./packetsonde_*.deb`,
  then the same operator next-steps.
- `packaging/README.md`: add the `debian/` artifacts to the file table.

## Testing / acceptance

Manual, on an Ubuntu 24.04 (or 22.04) host or chamber:

1. `sudo apt build-dep .` (or run `bootstrap-ubuntu.sh`) then
   `packaging/build-deb.sh` produces `packetsonde_0.1.4_amd64.deb` with no
   lintian-fatal errors.
2. `sudo apt install ./packetsonde_0.1.4_amd64.deb` installs cleanly;
   `packetsonde version` reports `0.1.4`.
3. The `packetsonded` system user exists; `systemctl is-enabled
   packetsonded` reports `disabled`; the service is not running.
4. `/etc/packetsonded/packetsonded.toml.example` present; live `.toml`
   absent; `keys/authorized/` owned by `packetsonded`.
5. After the operator next-steps (config + keygen + authorize + enable), the
   agent starts under systemd with the sandbox directives intact.
6. `sudo apt remove packetsonde` stops/disables the unit and removes binaries;
   `purge` removes config; the user remains.
7. Version-lockstep guard: bump `PS_VERSION_STR` without `dch` → `build-deb.sh`
   errors before invoking dpkg.
```
