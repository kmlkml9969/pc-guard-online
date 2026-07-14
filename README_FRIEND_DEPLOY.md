# PC Guard Friend Deployment

This is the no-zip deployment mode. Host these files as a plain web folder, then friends install PC Guard with one PowerShell command.

## Prepare the web folder

Run this in the project folder:

```powershell
powershell -ExecutionPolicy Bypass -File .\build_pc_guard_release.ps1
```

It creates:

```text
dist\pc-guard-web
```

Upload every file in that folder to a static web host, GitHub raw folder, private server, or object storage bucket.

If you already know the final hosted folder URL, generate with it:

```powershell
powershell -ExecutionPolicy Bypass -File .\build_pc_guard_release.ps1 -BaseUrl "https://your-host/pcguard"
```

## Friend install command

If you generated with `-BaseUrl`, friends can run the shortest form:

```powershell
iwr https://your-host/pcguard/install.ps1 -UseB | iex
```

If you did not generate with `-BaseUrl`, set the folder URL through an environment variable first:

```powershell
$env:PC_GUARD_BASE_URL = "https://your-host/pcguard"; iwr https://your-host/pcguard/install.ps1 -UseB | iex
```

What it does:

- Downloads the PC Guard files into a temporary folder.
- Installs Python and Node.js through winget if they are missing.
- Copies PC Guard to `%LOCALAPPDATA%\PCGuard`.
- Generates a new local token for that PC.
- Starts the local server and Windows agent.
- Adds startup launchers for the current Windows user.
- Installs/patches the OpenClaw Weixin plugin.
- Opens the WeChat authorization QR link and waits for one scan.

After scanning, send these messages to the WeChat ClawBot:

- `/pcstatus` - check PC state.
- `/pclock` - ask the PC to lock.
- `/pchelp` - show commands.

Chinese aliases for status, lock, and help are also enabled by the plugin patch.

## Reality checks

- A local Windows agent is required. Lock state, Win+L capture, and remote lock cannot work from the cloud alone.
- Personal WeChat authorization still requires one QR scan.
- Each install generates its own token. Do not share generated config files or logs.
- The agent only detects the Win+L combo. It does not record general keyboard input.
