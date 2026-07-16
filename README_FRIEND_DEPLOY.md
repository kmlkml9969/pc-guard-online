# PC Guard Security Friend Deployment

No npm or PyPI package is published. Friends install the repository files with one PowerShell command.

## Build the static folder

```powershell
powershell -ExecutionPolicy Bypass -File .\build_pc_guard_release.ps1 -BaseUrl "https://your-host/pcguard"
```

Upload everything from `dist\pc-guard-web` to the static host.

## Install

```powershell
curl.exe -L "https://your-host/pcguard/install.ps1" -o "$env:TEMP\pcguard-install.ps1"; powershell -ExecutionPolicy Bypass -File "$env:TEMP\pcguard-install.ps1"
```

The installer:

- installs Python with winget only when Python is missing;
- copies PC Guard to `%LOCALAPPDATA%\PCGuard`;
- creates local-only configuration and startup launchers;
- reuses a valid existing ClawBot authorization or displays a one-time QR code;
- disables competing OpenClaw Gateway use for the same bot session when permitted;
- starts the Win+L agent and direct Weixin security bridge.

Each friend must scan their own QR code and receives a separate owner allowlist. Generated account files, configuration, state, events, and logs must not be shared.

## Verify

After installation, send these messages to ClawBot:

```text
/pcstatus
/secstatus
/secnet
/secevents
```

The first security scan creates a baseline and does not produce alerts. Later firewall, RDP, remote-control process, listening-port, gateway, DNS, proxy, or network-category changes create queued alerts.
