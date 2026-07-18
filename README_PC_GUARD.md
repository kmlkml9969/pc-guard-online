# PC Guard Security

Windows lock monitoring, local security checks, and personal Weixin ClawBot alerts.

## Components

- `pc_guard_agent.py`: records Win+L, lock-like desktop state, and a local heartbeat. It does not record general keyboard input.
- `pc_guard_security.py`: read-only firewall, RDP, remote-control process, WiFi, gateway, DNS, proxy, and listening-port checks.
- `pc_guard_weixin_direct.py`: owner-only Weixin command handling, proactive security alerts, and weekday 18:30 lock reminders.
- Unlock camera alert: after the PC has been locked, an unlock outside weekday 09:00-18:00 captures one webcam photo and sends it to the bound Weixin user when media sending is available.
- `pc_guard_server.py`: legacy localhost relay. The current direct Weixin deployment does not require it.

Runtime data is stored in `%LOCALAPPDATA%\PCGuard`. The security monitor creates a baseline on its first successful scan and alerts only on later changes.

## Weixin commands

```text
/pcstatus       PC lock and Win+L status
/pclock         lock the PC
/secstatus      firewall, RDP, remote-control, and listener summary
/secevents      recent security events
/secports       non-loopback listening ports
/secnet         WiFi, gateway, DNS, proxy, and network category
/protect        harden PC-side network exposure
/unlockphoto    unlock camera alert status
/pchelp         command help
```

Chinese aliases are also supported. Commands from any Weixin user other than the QR-bound owner are rejected.

## Alerts

The first release alerts on:

- a Windows Firewall profile being disabled;
- RDP being enabled;
- a known remote-control process starting;
- a new non-loopback listening port;
- WiFi network category leaving Public;
- gateway IP/MAC, DNS, or system proxy changes.
- an unlock after lock outside the configured weekday quiet window, with a webcam photo when the camera and Weixin media sending are available.

Alerts are queued locally until Weixin delivery succeeds.

The `protect` command can enable Windows Firewall, set active non-domain networks to Public, disable Windows Remote Desktop, stop/disable Remote Registry and WinRM, and turn off common discovery/sharing firewall entry points when permissions allow it. It does not delete files, terminate arbitrary processes, change DNS, change VPN/proxy settings, or disconnect the network.

The unlock camera alert uses camera index `0` by default and is disabled on weekdays from 09:00 to 18:00. It captures any unlock event after a locked state; it cannot determine whether the person unlocking is the owner. If the camera is blocked by Windows privacy settings, the bot sends a failure notice instead.

## Limits

- Windows does not expose a complete audit trail for every screen-capture or keyboard-hook API.
- A sleeping, powered-off, or disconnected PC cannot send a live Weixin message. Pending events are sent after connectivity returns.
- Personal Weixin bot APIs can change and should not be the only notification channel for high-value systems.
