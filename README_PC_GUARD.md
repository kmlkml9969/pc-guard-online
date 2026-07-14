# PC Guard

Remote PC lock/sleep monitor and lock controller.

## Components

- `pc_guard_server.py`: relay server, mobile web UI, reminder scheduler, personal WeChat bot adapter.
- `pc_guard_agent.py`: Windows user-session agent. It reports lock-like state, heartbeat, foreground process, and Win+L-only hotkey captures.
- `install_pc_guard_agent_task.ps1`: creates a logon scheduled task for the agent.

## Personal WeChat bot integration

This project does not depend on an official WeChat API. It exposes a generic HTTP adapter for a personal WeChat bot plugin.

Inbound webhook:

```http
POST /wechat/inbound?token=YOUR_INBOUND_TOKEN
Content-Type: application/json
```

Supported inbound JSON field names:

- Text: `content`, `text`, `message`, `msg`, `Msg`, `Content`
- Sender: `from`, `from_user`, `fromUser`, `fromUserName`, `sender`, `wxid`, `roomid`

Supported commands:

- `status` or Chinese `status` words: returns PC online/lock/sleep-like state.
- `lock` or Chinese lock words: queues a remote lock command.
- `help`: returns command help.

Typical payload:

```json
{
  "from": "wxid_xxx",
  "content": "status"
}
```

Typical response:

```json
{
  "reply": "...",
  "to": "wxid_xxx",
  "handled": true
}
```

If your WeChat plugin supports "reply by HTTP response", use the `reply` field.

If your plugin requires a separate send-message API, configure:

```json
{
  "personal_wechat_bot": {
    "enabled": true,
    "inbound_token": "YOUR_INBOUND_TOKEN",
    "send_url": "http://127.0.0.1:PORT/send",
    "send_token": "OPTIONAL_SEND_TOKEN",
    "default_to": "wxid_xxx"
  }
}
```

The server will POST this JSON to `send_url`:

```json
{
  "to": "wxid_xxx",
  "content": "message text",
  "text": "message text",
  "type": "text"
}
```

## Start server

```powershell
Copy-Item .\pc_guard_server_config.example.json .\pc_guard_config.json
python .\pc_guard_server.py --config .\pc_guard_config.json
```

Mobile web UI:

```text
https://YOUR_DOMAIN/ui?token=YOUR_SHARED_TOKEN
```

## Start Windows agent

```powershell
Copy-Item .\pc_guard_agent_config.example.json .\pc_guard_agent_config.json
python .\pc_guard_agent.py --config .\pc_guard_agent_config.json
```

Install logon scheduled task:

```powershell
.\install_pc_guard_agent_task.ps1
```

## Reminder

The server sends a reminder at 18:30 on weekdays. It can send through:

- personal WeChat bot `send_url`
- Bark
- ntfy
- WeCom webhook, if configured

## Limits

- Past Win+L events cannot be recovered unless this agent was already running.
- Personal WeChat bot plugins are unofficial. Use your own plugin's HTTP API and account-risk policy.
- If the PC is asleep, it cannot execute a remote lock command until it wakes up and the agent polls the server.
