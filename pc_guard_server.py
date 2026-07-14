import argparse
import json
import os
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import subprocess
from datetime import datetime, time as dt_time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from zoneinfo import ZoneInfo


DEFAULT_CONFIG = {
    "bind_host": "0.0.0.0",
    "bind_port": 8787,
    "timezone": "Asia/Shanghai",
    "shared_token": "CHANGE_ME_LONG_RANDOM_TOKEN",
    "stale_after_seconds": 120,
    "reminder": {
        "enabled": True,
        "weekdays_only": True,
        "time": "18:30",
        "window_seconds": 300,
    },
    "notifications": {
        "ntfy_url": "",
        "bark_url": "",
        "wecom_webhook": "",
    },
    "personal_wechat_bot": {
        "enabled": False,
        "inbound_token": "",
        "send_url": "",
        "send_token": "",
        "default_to": "",
    },
    "openclaw_weixin": {
        "enabled": False,
        "channel": "openclaw-weixin",
        "account": "",
        "target": "",
        "openclaw_cmd": "",
    },
}


STATUS_WORDS = {
    "status",
    "state",
    "\u72b6\u6001",
    "\u7535\u8111\u72b6\u6001",
    "\u67e5\u72b6\u6001",
    "\u67e5\u8be2\u72b6\u6001",
}
LOCK_WORDS = {"lock", "\u9501\u5c4f", "\u9501\u5b9a", "\u9501\u7535\u8111"}
HELP_WORDS = {"help", "\u5e2e\u52a9", "?"}


def merge_config(base: dict, raw: dict) -> dict:
    result = base.copy()
    for key, value in raw.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            merged = result[key].copy()
            merged.update(value)
            result[key] = merged
        else:
            result[key] = value
    return result


def load_config(path: str) -> dict:
    raw = {}
    if path and Path(path).exists():
        raw = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    config = merge_config(DEFAULT_CONFIG, raw)
    env_token = os.getenv("PC_GUARD_TOKEN")
    if env_token:
        config["shared_token"] = env_token
    return config


class GuardState:
    def __init__(self, config: dict):
        self.config = config
        self.lock = threading.Lock()
        self.last_heartbeat = None
        self.last_state = {}
        self.pending_command = None
        self.last_command_result = None
        self.last_reminder_date = None

    def snapshot(self) -> dict:
        with self.lock:
            now = now_ts(self.config)
            stale_after = int(self.config["stale_after_seconds"])
            age = None
            online = False
            sleep_like = True
            if self.last_heartbeat:
                age = max(0, int(now - self.last_heartbeat))
                online = age <= stale_after
                sleep_like = not online
            return {
                "now": iso_now(self.config),
                "online": online,
                "sleep_like": sleep_like,
                "heartbeat_age_seconds": age,
                "last_heartbeat": iso_from_ts(self.last_heartbeat, self.config) if self.last_heartbeat else None,
                "state": self.last_state,
                "pending_command": self.pending_command,
                "last_command_result": self.last_command_result,
            }

    def update_heartbeat(self, payload: dict) -> dict:
        with self.lock:
            self.last_heartbeat = now_ts(self.config)
            self.last_state = payload
            command = self.pending_command
            self.pending_command = None
            return command or {}

    def queue_command(self, action: str) -> dict:
        command = {
            "id": secrets.token_hex(8),
            "action": action,
            "queued_at": iso_now(self.config),
        }
        with self.lock:
            self.pending_command = command
        return command

    def save_command_result(self, payload: dict) -> None:
        with self.lock:
            self.last_command_result = payload


def now_ts(config: dict) -> float:
    return datetime.now(ZoneInfo(config["timezone"])).timestamp()


def iso_now(config: dict) -> str:
    return datetime.now(ZoneInfo(config["timezone"])).isoformat(timespec="seconds")


def iso_from_ts(ts: float, config: dict) -> str:
    return datetime.fromtimestamp(ts, ZoneInfo(config["timezone"])).isoformat(timespec="seconds")


def token_from_request(handler: BaseHTTPRequestHandler) -> str:
    parsed = urllib.parse.urlparse(handler.path)
    params = urllib.parse.parse_qs(parsed.query)
    return (
        handler.headers.get("X-PC-GUARD-TOKEN")
        or handler.headers.get("X-WECHAT-BOT-TOKEN")
        or params.get("token", [""])[0]
    )


def require_token(handler: BaseHTTPRequestHandler, expected: str) -> bool:
    supplied = token_from_request(handler)
    if secrets.compare_digest(str(supplied), str(expected)):
        return True
    send_json(handler, 401, {"error": "unauthorized"})
    return False


def read_json(handler: BaseHTTPRequestHandler) -> dict:
    length = int(handler.headers.get("Content-Length") or "0")
    if length <= 0:
        return {}
    raw = handler.rfile.read(length)
    return json.loads(raw.decode("utf-8-sig"))


def send_json(handler: BaseHTTPRequestHandler, status: int, payload: dict) -> None:
    raw = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Content-Length", str(len(raw)))
    handler.end_headers()
    handler.wfile.write(raw)


def send_html(handler: BaseHTTPRequestHandler, html: str) -> None:
    raw = html.encode("utf-8")
    handler.send_response(200)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Content-Length", str(len(raw)))
    handler.end_headers()
    handler.wfile.write(raw)


def status_line(snapshot: dict) -> str:
    state = snapshot.get("state") or {}
    win_l = state.get("win_l") or {}
    if not snapshot.get("last_heartbeat"):
        headline = "\u6ca1\u6709\u6536\u5230\u8fc7\u7535\u8111\u5fc3\u8df3"
    elif not snapshot.get("online"):
        headline = "\u79bb\u7ebf\uff0c\u7591\u4f3c\u4f11\u7720/\u5173\u673a/\u65ad\u7f51"
    elif state.get("locked_like"):
        headline = "\u5df2\u9501\u5c4f\u6216\u5904\u4e8e\u9501\u5c4f\u754c\u9762"
    else:
        headline = "\u672a\u9501\u5c4f"
    return (
        f"\u7535\u8111\u72b6\u6001\uff1a{headline}\n"
        f"\u6700\u540e\u5fc3\u8df3\uff1a{snapshot.get('last_heartbeat') or '\u65e0'}\n"
        f"\u5fc3\u8df3\u5e74\u9f84\uff1a{snapshot.get('heartbeat_age_seconds') if snapshot.get('heartbeat_age_seconds') is not None else '\u65e0'} \u79d2\n"
        f"\u6700\u8fd1 Win+L\uff1a{win_l.get('last_win_l_at') or '\u672a\u6355\u83b7'}\n"
        f"\u524d\u53f0\u8fdb\u7a0b\uff1a{state.get('foreground_process') or '\u672a\u77e5'}\n"
        f"\u670d\u52a1\u5668\u65f6\u95f4\uff1a{snapshot.get('now')}"
    )


def help_text() -> str:
    return (
        "\u53ef\u7528\u547d\u4ee4\uff1a\n"
        "\u72b6\u6001 - \u67e5\u770b\u7535\u8111\u662f\u5426\u5728\u7ebf/\u9501\u5c4f/\u4f11\u7720\n"
        "\u9501\u5c4f - \u8bf7\u6c42\u7535\u8111\u6267\u884c\u9501\u5c4f\n"
        "\u5e2e\u52a9 - \u663e\u793a\u547d\u4ee4"
    )


def mobile_html(token: str) -> str:
    escaped = urllib.parse.quote(token, safe="")
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PC Guard</title>
<style>
body{{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f6f7f9;color:#111827}}
main{{max-width:680px;margin:0 auto;padding:24px}}
.panel{{background:white;border:1px solid #e5e7eb;border-radius:8px;padding:18px;margin-bottom:14px}}
h1{{font-size:24px;margin:0 0 18px}}
.status{{font-size:28px;font-weight:700;margin:8px 0}}
.muted{{color:#6b7280;font-size:14px;line-height:1.5}}
button{{width:100%;border:0;border-radius:8px;padding:15px 18px;background:#111827;color:white;font-size:17px;font-weight:650}}
button:disabled{{opacity:.55}}
pre{{white-space:pre-wrap;word-break:break-word;background:#f3f4f6;border-radius:8px;padding:12px;font-size:12px}}
</style>
</head>
<body>
<main>
<h1>PC Guard</h1>
<section class="panel">
  <div class="muted" id="time">Loading...</div>
  <div class="status" id="headline">-</div>
  <div class="muted" id="detail"></div>
</section>
<section class="panel">
  <button id="lockBtn" onclick="lockPc()">Lock PC</button>
</section>
<section class="panel">
  <div class="muted">Raw status</div>
  <pre id="raw"></pre>
</section>
</main>
<script>
const token = "{escaped}";
async function api(path, options) {{
  const res = await fetch(path + (path.includes("?") ? "&" : "?") + "token=" + token, options);
  if (!res.ok) throw new Error(await res.text());
  return await res.json();
}}
function render(data) {{
  const s = data.state || {{}};
  const winL = s.win_l || {{}};
  let headline = "Offline / sleep-like";
  if (data.online) headline = s.locked_like ? "Locked or lock screen" : "Unlocked";
  document.getElementById("headline").textContent = headline;
  document.getElementById("time").textContent = "Server time " + data.now;
  document.getElementById("detail").textContent =
    "Last heartbeat " + (data.last_heartbeat || "none") +
    ", age " + (data.heartbeat_age_seconds ?? "none") + " sec. " +
    "Last Win+L " + (winL.last_win_l_at || "not captured") + ".";
  document.getElementById("raw").textContent = JSON.stringify(data, null, 2);
}}
async function refresh() {{
  try {{ render(await api("/api/status")); }}
  catch (e) {{ document.getElementById("headline").textContent = "Read failed"; document.getElementById("detail").textContent = e.message; }}
}}
async function lockPc() {{
  const btn = document.getElementById("lockBtn");
  btn.disabled = true;
  try {{ await api("/api/lock", {{method:"POST"}}); await refresh(); }}
  catch (e) {{ alert(e.message); }}
  finally {{ btn.disabled = false; }}
}}
refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>"""


def post_text(url: str, body: bytes, content_type: str = "text/plain; charset=utf-8", headers=None) -> None:
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", content_type)
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    with urllib.request.urlopen(req, timeout=8) as response:
        response.read()


def send_personal_wechat(config: dict, text: str, to_user: str = "") -> bool:
    bot = config.get("personal_wechat_bot") or {}
    if not bot.get("enabled") or not bot.get("send_url"):
        return False
    payload = {
        "to": to_user or bot.get("default_to") or "",
        "content": text,
        "text": text,
        "type": "text",
    }
    headers = {}
    if bot.get("send_token"):
        headers["X-WECHAT-BOT-TOKEN"] = bot["send_token"]
    raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    post_text(bot["send_url"], raw, "application/json; charset=utf-8", headers)
    return True


def send_notification(config: dict, text: str) -> None:
    notifications = config.get("notifications", {})
    errors = []
    ntfy_url = notifications.get("ntfy_url") or ""
    bark_url = notifications.get("bark_url") or ""
    wecom_webhook = notifications.get("wecom_webhook") or ""
    if ntfy_url:
        try:
            post_text(ntfy_url, text.encode("utf-8"))
        except (urllib.error.URLError, TimeoutError) as exc:
            errors.append(f"ntfy: {exc}")
    if bark_url:
        try:
            title = urllib.parse.quote("PC Guard")
            body = urllib.parse.quote(text)
            with urllib.request.urlopen(f"{bark_url.rstrip('/')}/{title}/{body}", timeout=8) as response:
                response.read()
        except (urllib.error.URLError, TimeoutError) as exc:
            errors.append(f"bark: {exc}")
    if wecom_webhook:
        try:
            payload = json.dumps({"msgtype": "text", "text": {"content": text}}, ensure_ascii=False).encode("utf-8")
            post_text(wecom_webhook, payload, "application/json; charset=utf-8")
        except (urllib.error.URLError, TimeoutError) as exc:
            errors.append(f"wecom: {exc}")
    try:
        send_personal_wechat(config, text)
    except (urllib.error.URLError, TimeoutError) as exc:
        errors.append(f"personal_wechat: {exc}")
    try:
        send_openclaw_weixin(config, text)
    except Exception as exc:
        errors.append(f"openclaw_weixin: {exc}")
    if errors:
        print("notification errors:", "; ".join(errors), flush=True)


def send_openclaw_weixin(config: dict, text: str) -> bool:
    wx = config.get("openclaw_weixin") or {}
    if not wx.get("enabled"):
        return False
    account = str(wx.get("account") or "").strip()
    target = str(wx.get("target") or "").strip()
    if not account or not target:
        raise RuntimeError("openclaw_weixin.account and target are required")
    cmd = str(wx.get("openclaw_cmd") or "").strip() or str(Path.home() / "AppData" / "Roaming" / "npm" / "openclaw.cmd")
    args = [
        cmd,
        "message",
        "send",
        "--channel",
        str(wx.get("channel") or "openclaw-weixin"),
        "--account",
        account,
        "--target",
        target,
        "--message",
        text,
        "--json",
    ]
    result = subprocess.run(
        args,
        cwd=str(Path(__file__).resolve().parent),
        capture_output=True,
        timeout=60,
    )
    if result.returncode != 0:
        output = (result.stderr or result.stdout or b"").decode("utf-8", errors="replace")
        raise RuntimeError(output.strip()[:500])
    return True


def parse_iso_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def had_win_l_today(snapshot: dict) -> bool:
    state = snapshot.get("state") or {}
    win_l = state.get("win_l") or {}
    last_win_l = parse_iso_datetime(win_l.get("last_win_l_at"))
    now = parse_iso_datetime(snapshot.get("now"))
    return bool(last_win_l and now and last_win_l.date() == now.date())


def reminder_text(snapshot: dict) -> str:
    state = snapshot.get("state") or {}
    win_l = state.get("win_l") or {}
    last_win_l_text = win_l.get("last_win_l_at") or "\u672a\u6355\u83b7"
    locked_now = bool(snapshot.get("online") and state.get("locked_like"))
    win_l_today = had_win_l_today(snapshot)

    if locked_now or win_l_today:
        headline = "\u5df2\u9501\u5c4f"
        detail = "\u5df2\u68c0\u6d4b\u5230\u4eca\u5929\u7684\u9501\u5c4f\u72b6\u6001\u6216 Win+L \u64cd\u4f5c\u3002"
    elif not snapshot.get("last_heartbeat"):
        headline = "\u65e0\u6cd5\u786e\u8ba4"
        detail = "\u8fd8\u6ca1\u6536\u5230\u8fc7\u7535\u8111\u5fc3\u8df3\uff0c\u8bf7\u786e\u8ba4\u7535\u8111\u662f\u5426\u5df2\u9501\u5c4f\u3002"
    elif not snapshot.get("online"):
        headline = "\u7535\u8111\u79bb\u7ebf/\u7591\u4f3c\u4f11\u7720"
        detail = "\u6ca1\u68c0\u6d4b\u5230\u4eca\u5929\u7684 Win+L\u3002\u5982\u679c\u4e0d\u662f\u4f60\u4e3b\u52a8\u4f11\u7720\u6216\u5408\u76d6\uff0c\u8bf7\u786e\u8ba4\u9501\u5c4f\u3002"
    else:
        headline = "\u8bf7\u9501\u5c4f"
        detail = "\u76ee\u524d\u6ca1\u68c0\u6d4b\u5230\u4eca\u5929\u7684\u9501\u5c4f\u72b6\u6001\u6216 Win+L \u64cd\u4f5c\uff0c\u8bf7\u73b0\u5728\u9501\u5c4f\u3002"

    return (
        f"18:30 \u4e0b\u73ed\u9501\u5c4f\u63d0\u9192\uff1a{headline}\n"
        f"{detail}\n"
        f"\u6700\u8fd1 Win+L\uff1a{last_win_l_text}\n"
        f"\u6700\u540e\u5fc3\u8df3\uff1a{snapshot.get('last_heartbeat') or '\u65e0'}\n"
        f"\u670d\u52a1\u5668\u65f6\u95f4\uff1a{snapshot.get('now')}"
    )


def scheduler_loop(state: GuardState) -> None:
    config = state.config
    reminder = config.get("reminder", {})
    target_hour, target_minute = [int(part) for part in reminder.get("time", "18:30").split(":", 1)]
    window_seconds = int(reminder.get("window_seconds", 300))
    zone = ZoneInfo(config["timezone"])
    while True:
        try:
            now = datetime.now(zone)
            enabled = bool(reminder.get("enabled", True))
            weekday_ok = (not reminder.get("weekdays_only", True)) or now.weekday() < 5
            target = now.replace(hour=target_hour, minute=target_minute, second=0, microsecond=0)
            elapsed = (now - target).total_seconds()
            due = 0 <= elapsed < window_seconds
            today = now.date().isoformat()
            if enabled and weekday_ok and due and state.last_reminder_date != today:
                send_notification(config, reminder_text(state.snapshot()))
                state.last_reminder_date = today
        except Exception as exc:
            print(f"scheduler error: {exc}", flush=True)
        time.sleep(20)


def find_first(payload: dict, names: tuple[str, ...]) -> str:
    for name in names:
        value = payload.get(name)
        if value is not None:
            return str(value)
    for value in payload.values():
        if isinstance(value, dict):
            found = find_first(value, names)
            if found:
                return found
    return ""


def extract_wechat_message(payload: dict) -> tuple[str, str]:
    text = find_first(payload, ("content", "text", "message", "msg", "Msg", "Content"))
    sender = find_first(payload, ("from", "from_user", "fromUser", "fromUserName", "sender", "wxid", "roomid"))
    return text.strip(), sender.strip()


def handle_wechat_command(state: GuardState, payload: dict) -> dict:
    text, sender = extract_wechat_message(payload)
    normalized = text.strip().lower()
    if normalized in STATUS_WORDS:
        reply = status_line(state.snapshot())
    elif normalized in LOCK_WORDS:
        command = state.queue_command("lock")
        reply = f"\u5df2\u4e0b\u53d1\u9501\u5c4f\u547d\u4ee4\uff1a{command['id']}\n\u7535\u8111\u5728\u7ebf\u65f6\u4f1a\u5728\u4e0b\u4e00\u6b21\u5fc3\u8df3\u6267\u884c\u3002"
    elif normalized in HELP_WORDS:
        reply = help_text()
    else:
        reply = "\u672a\u8bc6\u522b\u547d\u4ee4\u3002\n" + help_text()
    return {"reply": reply, "to": sender, "handled": True}


def make_handler(state: GuardState):
    config = state.config

    class Handler(BaseHTTPRequestHandler):
        server_version = "PcGuard/1.1"

        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path in ("/", "/ui"):
                params = urllib.parse.parse_qs(parsed.query)
                token = params.get("token", [""])[0]
                if not require_token(self, config["shared_token"]):
                    return
                send_html(self, mobile_html(token))
                return
            if parsed.path == "/api/status":
                if not require_token(self, config["shared_token"]):
                    return
                send_json(self, 200, state.snapshot())
                return
            send_json(self, 404, {"error": "not found"})

        def do_POST(self):
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == "/api/heartbeat":
                if not require_token(self, config["shared_token"]):
                    return
                command = state.update_heartbeat(read_json(self))
                send_json(self, 200, {"command": command})
                return
            if parsed.path == "/api/lock":
                if not require_token(self, config["shared_token"]):
                    return
                send_json(self, 200, {"queued": state.queue_command("lock")})
                return
            if parsed.path == "/api/command_result":
                if not require_token(self, config["shared_token"]):
                    return
                state.save_command_result(read_json(self))
                send_json(self, 200, {"ok": True})
                return
            if parsed.path == "/api/test_notification":
                if not require_token(self, config["shared_token"]):
                    return
                send_notification(config, "PC Guard notification test: " + iso_now(config))
                send_json(self, 200, {"ok": True})
                return
            if parsed.path == "/wechat/inbound":
                bot = config.get("personal_wechat_bot") or {}
                expected = bot.get("inbound_token") or config["shared_token"]
                if not require_token(self, expected):
                    return
                result = handle_wechat_command(state, read_json(self))
                if bot.get("send_url"):
                    try:
                        send_personal_wechat(config, result["reply"], result.get("to", ""))
                    except (urllib.error.URLError, TimeoutError) as exc:
                        result["send_error"] = str(exc)
                send_json(self, 200, result)
                return
            send_json(self, 404, {"error": "not found"})

        def log_message(self, fmt, *args):
            print(f"{self.address_string()} - {fmt % args}", flush=True)

    return Handler


def main() -> None:
    parser = argparse.ArgumentParser(description="PC Guard relay server")
    parser.add_argument("--config", default="pc_guard_config.json")
    args = parser.parse_args()
    config = load_config(args.config)
    state = GuardState(config)
    threading.Thread(target=scheduler_loop, args=(state,), daemon=True).start()
    server = ThreadingHTTPServer((config["bind_host"], int(config["bind_port"])), make_handler(state))
    print(f"PC Guard server listening on http://{config['bind_host']}:{config['bind_port']}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
