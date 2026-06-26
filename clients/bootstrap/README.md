# client-bootstrap

Easy, idempotent provisioning of an **mTLS client identity** for the packetsonde
agent's certificate-authenticated TCP IPC listener. Each script generates a
client keypair, authorizes it with the local agent (drops the pubkey in the
agent's `authorized/` dir, creating the agent identity if absent), and prints
the agent fingerprint to pin plus a ready-to-run `psctl` connect command.

| Platform | Script | Agent location |
|---|---|---|
| Linux / macOS / SteamOS | `client-bootstrap.sh` | local native agent |
| Windows | `client-bootstrap.ps1` | agent in WSL (no native Windows agent) |

## Linux / macOS / SteamOS

```sh
./client-bootstrap.sh                       # name=ui, listen=127.0.0.1:4701
./client-bootstrap.sh --name dashboard --listen 0.0.0.0:4701 --launch
```
Env: `PS_KEY_DIR` (default `~/.config/packetsonde/keys`), `PACKETSONDE` (CLI path;
falls back to `../../build/src/cli/packetsonde` for dev builds). `--launch` also
starts the agent in the foreground with mTLS for a quick try.

## Windows (agent in WSL)

```powershell
.\client-bootstrap.ps1 -Psctl .\psctl.exe
# params: -Distro kali-linux  -ClientName ui  -OutDir %USERPROFILE%\.packetsonde
#         -WslKeyDir '$HOME/.config/packetsonde/keys'  -Port 4701
#         -PacketsondeBin /path/to/packetsonde   (WSL CLI; default = dev build path)
```
The client seed stays on Windows (for the UE UI / `psctl.exe`); only the pubkey
is pushed into the WSL agent. Agent-side steps run as `root` in the distro.

### WSL networking note
The agent in WSL must listen so Windows can reach it:

- **Mirrored networking (recommended):** put this in `%USERPROFILE%\.wslconfig`,
  then `wsl --shutdown`:
  ```ini
  [wsl2]
  networkingMode=mirrored
  ```
  Then Windows reaches the agent at `127.0.0.1:<port>` (bind the agent to
  `0.0.0.0` or `127.0.0.1`).
- **Default NAT mode:** Windows `localhost` forwarding can be unreliable; use the
  distro's IP instead (`wsl hostname -I`), e.g. `--host 172.x.x.x`. Note that IP
  changes across reboots — prefer mirrored mode for a stable `127.0.0.1`.

## Then connect

```
psctl --host <host> --port <port> --key <client>.sec --agent-fpr sha256:<hex> hosts
```
The agent must run with mTLS TCP enabled: `[network] listen=<addr:port>` + `tls=1`
(or `PS_NETWORK_LISTEN` + `PS_NETWORK_TLS=1`). See `../go/psctl`.
