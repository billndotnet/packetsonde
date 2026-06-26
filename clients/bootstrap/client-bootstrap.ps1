<#
.SYNOPSIS
  Provision an mTLS client identity (for the UE UI / psctl.exe) against a
  packetsonde agent running in WSL. Windows has no native agent, so the agent
  side is configured inside the WSL distro.

.DESCRIPTION
  1. generates a client keypair on Windows with psctl.exe (the seed stays on
     Windows, owned by the UI),
  2. copies the client pubkey into the WSL agent's authorized-keys dir
     (generating the agent identity if absent),
  3. reads the agent fingerprint to pin,
  4. prints a ready-to-run psctl.exe connect command.

  The agent must then run in WSL with mTLS TCP enabled, e.g.:
    PS_KEY_DIR=<keydir> PS_NETWORK_LISTEN=0.0.0.0:4701 PS_NETWORK_TLS=1 packetsonded
  WSL2 forwards localhost, so Windows reaches it at 127.0.0.1:<port>.

.EXAMPLE
  .\client-bootstrap.ps1 -Psctl .\psctl.exe
#>
[CmdletBinding()]
param(
  [string]$Distro         = "kali-linux",
  [string]$ClientName     = "ui",
  [string]$OutDir         = "$env:USERPROFILE\.packetsonde",
  [string]$Psctl          = "",
  [string]$WslKeyDir      = '$HOME/.config/packetsonde/keys',
  [string]$PacketsondeBin = "/home/billn/packetsonde/build/src/cli/packetsonde",
  [string]$VMHost         = "127.0.0.1",
  [int]$Port              = 4701,
  # UE mode: authorize the UE UI's own identity instead of a standalone client.
  # Point this at the project's Saved\agent-id dir (the UI's keystore). The key
  # is created in-place if absent (same raw format the UI's LoadOrCreate uses),
  # then authorized; the script prints the editor env vars to set.
  [string]$UeIdentityDir  = ""
)
$ErrorActionPreference = "Stop"

# Convert a Windows path to its /mnt/<drive>/... WSL form without invoking
# wsl wslpath (which mangles backslashes when called from PowerShell).
function ConvertTo-WslPath([string]$p) {
  $full  = [IO.Path]::GetFullPath($p)
  $drive = $full.Substring(0,1).ToLower()
  $rest  = ($full.Substring(2)) -replace '\\','/'
  return "/mnt/$drive$rest"
}

# --- locate psctl.exe ------------------------------------------------------
if (-not $Psctl) {
  $cand = Join-Path $PSScriptRoot "psctl.exe"
  if (Test-Path $cand) { $Psctl = $cand }
  elseif (Get-Command psctl.exe -ErrorAction SilentlyContinue) { $Psctl = "psctl.exe" }
  else { throw "psctl.exe not found. Build it (GOOS=windows go build) and pass -Psctl <path>." }
}

$isUe = -not [string]::IsNullOrEmpty($UeIdentityDir)
if ($isUe) {
  New-Item -ItemType Directory -Force -Path $UeIdentityDir | Out-Null
  $prefix  = Join-Path $UeIdentityDir "agent"   # the UE keystore name is "agent"
  $authName = "ue"
  $idLabel = "UE UI identity"
} else {
  New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
  $prefix  = Join-Path $OutDir $ClientName
  $authName = $ClientName
  $idLabel = "client identity '$ClientName'"
}
$pubWin = "$prefix.pub"

# --- 1. client/UE identity (idempotent: never clobber an existing key) ------
if (Test-Path $pubWin) {
  Write-Host "==> reusing existing $idLabel at $prefix.{sec,pub}"
} else {
  Write-Host "==> generating $idLabel at $prefix.{sec,pub}"
  & $Psctl gen-key $prefix
  if (-not (Test-Path $pubWin)) { throw "psctl gen-key did not produce $pubWin" }
}

# --- 2+3. authorize in WSL + fetch agent fingerprint -----------------------
# Run the agent-side work via a generated bash script (avoids cross-shell
# quoting pain). PS interpolates the path vars; `$ stays literal for bash.
$pubWsl = ConvertTo-WslPath $pubWin
$inner = @"
#!/bin/bash
set -e
export PS_KEY_DIR="$WslKeyDir"
mkdir -p "`$PS_KEY_DIR/authorized"
chmod 700 "`$PS_KEY_DIR" 2>/dev/null || true
if [ ! -f "`$PS_KEY_DIR/agent.sec" ]; then
  "$PacketsondeBin" key generate --name agent >/dev/null
fi
cp -f "$pubWsl" "`$PS_KEY_DIR/authorized/$authName.pub"
echo "AUTHORIZED `$PS_KEY_DIR/authorized/$authName.pub"
"$PacketsondeBin" key fingerprint agent | grep -oE 'sha256:[0-9a-f]+' | head -1
"@
$innerPath = Join-Path $env:TEMP "ps-client-bootstrap-inner.sh"
# write LF-only so bash is happy
[IO.File]::WriteAllText($innerPath, ($inner -replace "`r`n","`n"))
$innerWsl = ConvertTo-WslPath $innerPath
# Run the agent-side work as root: avoids the systemd user-session warning and
# any keystore permission issues. (Adjust ownership for your agent's run user.)
$out = & wsl -d $Distro -u root -- bash $innerWsl
$out | ForEach-Object { Write-Host "   $_" }
$agentFpr = ($out | Select-String -Pattern 'sha256:[0-9a-f]+').Matches.Value | Select-Object -Last 1

# --- 4. print next steps ----------------------------------------------------
$daemon = $PacketsondeBin -replace 'cli/packetsonde','agent/packetsonded'
Write-Host ""
Write-Host "================ bootstrap complete ================"
Write-Host "identity  : $prefix.sec   (keep private)"
Write-Host "agent fpr : $agentFpr"
Write-Host ""
Write-Host "Run the WSL agent with mTLS TCP enabled, e.g.:"
Write-Host "  wsl -d $Distro -- env PS_KEY_DIR=$WslKeyDir PS_NETWORK_LISTEN=0.0.0.0:$Port PS_NETWORK_TLS=1 $daemon"
Write-Host ""
if ($isUe) {
  Write-Host "Then launch the UE editor with these env vars (the UI auto-connects):"
  Write-Host "  PS_AGENT_TCP=${VMHost}:${Port}"
  Write-Host "  PS_AGENT_FINGERPRINT=$agentFpr"
} else {
  Write-Host "Then connect from Windows:"
  Write-Host "  $Psctl --host $VMHost --port $Port --key `"$prefix.sec`" --agent-fpr $agentFpr hosts"
}
Write-Host "===================================================="
