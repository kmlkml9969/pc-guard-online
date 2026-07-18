import argparse
import base64
import ctypes
import json
import os
import random
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime
from pathlib import Path

from pc_guard_security import (
    SecurityMonitor,
    apply_network_protection,
    format_network_protection,
    format_security_events,
    format_security_network,
    format_security_ports,
    format_security_status,
)


CHANNEL_VERSION = "1.0.3"
TEXT = 1
BOT = 2
FINISH = 2
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
DEFAULT_UNLOCK_CAMERA_ALERT = {
    "enabled": True,
    "disabled_weekdays_only": True,
    "disabled_start": "09:00",
    "disabled_end": "18:00",
    "camera_index": 0,
    "cooldown_seconds": 300,
    "capture_delay_seconds": 1.5,
}


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def stop_competing_openclaw_gateway() -> None:
    script = r"""
$ErrorActionPreference = 'SilentlyContinue'
Get-CimInstance Win32_Process -Filter "name = 'node.exe'" | Where-Object {
  $_.CommandLine -match 'openclaw.*gateway|gateway.*18789'
} | ForEach-Object {
  Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
}
"""
    try:
        subprocess.run(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "-"],
            input=script.encode("ascii"),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=12,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception as exc:
        print(f"could not stop competing OpenClaw Gateway: {exc}", flush=True)


def find_account(openclaw_dir: Path, account_id: str | None) -> tuple[str, dict]:
    accounts_path = openclaw_dir / "openclaw-weixin" / "accounts.json"
    accounts = json.loads(accounts_path.read_text(encoding="utf-8-sig"))
    if not accounts:
        raise RuntimeError("No Weixin ClawBot account found")
    selected = account_id or accounts[-1]
    account_path = openclaw_dir / "openclaw-weixin" / "accounts" / f"{selected}.json"
    return selected, read_json(account_path)


def random_uin_header() -> str:
    return base64.b64encode(str(random.getrandbits(32)).encode("utf-8")).decode("ascii")


def post_json(base_url: str, endpoint: str, token: str, body: dict, timeout: int = 40) -> dict:
    url = urllib.parse.urljoin(base_url.rstrip("/") + "/", endpoint)
    raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=raw, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Content-Length", str(len(raw)))
    req.add_header("AuthorizationType", "ilink_bot_token")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("X-WECHAT-UIN", random_uin_header())
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=timeout) as resp:
        text = resp.read().decode("utf-8")
    return json.loads(text) if text else {}


def get_updates(base_url: str, token: str, buf: str) -> dict:
    return post_json(
        base_url,
        "ilink/bot/getupdates",
        token,
        {"get_updates_buf": buf, "base_info": {"channel_version": CHANNEL_VERSION}},
        timeout=20,
    )


def send_message(base_url: str, token: str, to_user_id: str, text: str, context_token: str | None) -> None:
    post_json(
        base_url,
        "ilink/bot/sendmessage",
        token,
        {
            "msg": {
                "from_user_id": "",
                "to_user_id": to_user_id,
                "client_id": "pcguard-" + uuid.uuid4().hex,
                "message_type": BOT,
                "message_state": FINISH,
                "item_list": [{"type": TEXT, "text_item": {"text": text}}],
                "context_token": context_token or None,
            },
            "base_info": {"channel_version": CHANNEL_VERSION},
        },
        timeout=20,
    )


def send_media_with_openclaw(
    account_id: str,
    to_user_id: str,
    text: str,
    media_path: Path,
    timeout: int = 45,
) -> None:
    openclaw_cmd = Path(os.environ.get("APPDATA", "")) / "npm" / "openclaw.cmd"
    if not openclaw_cmd.exists():
        raise RuntimeError(f"openclaw.cmd not found: {openclaw_cmd}")
    completed = subprocess.run(
        [
            str(openclaw_cmd),
            "message",
            "send",
            "--channel",
            "openclaw-weixin",
            "--account",
            account_id,
            "--target",
            to_user_id,
            "--message",
            text,
            "--media",
            str(media_path),
            "--json",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode != 0:
        stdout = completed.stdout.decode("utf-8", errors="replace")[-500:]
        stderr = completed.stderr.decode("utf-8", errors="replace")[-500:]
        raise RuntimeError(f"openclaw media send failed rc={completed.returncode} stdout={stdout} stderr={stderr}")


def pc_api(config: dict, path: str, method: str = "GET") -> dict:
    base = f"http://{config.get('bind_host', '127.0.0.1')}:{int(config.get('bind_port', 8787))}"
    url = urllib.parse.urljoin(base, path)
    req = urllib.request.Request(url, method=method)
    req.add_header("X-PC-GUARD-TOKEN", str(config["shared_token"]))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def iso_now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def get_input_desktop_name() -> str:
    user32.OpenInputDesktop.argtypes = [ctypes.c_ulong, ctypes.c_bool, ctypes.c_ulong]
    user32.OpenInputDesktop.restype = ctypes.c_void_p
    user32.CloseDesktop.argtypes = [ctypes.c_void_p]
    user32.GetUserObjectInformationW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_ulong),
    ]
    handle = user32.OpenInputDesktop(0, False, 0x0001)
    if not handle:
        return f"ERR:{ctypes.get_last_error()}"
    try:
        needed = ctypes.c_ulong()
        buffer = ctypes.create_unicode_buffer(256)
        ok = user32.GetUserObjectInformationW(handle, 2, buffer, ctypes.sizeof(buffer), ctypes.byref(needed))
        if not ok:
            return f"ERRINFO:{ctypes.get_last_error()}"
        return buffer.value
    finally:
        user32.CloseDesktop(handle)


def get_foreground_process_name() -> str:
    user32.GetForegroundWindow.restype = ctypes.c_void_p
    user32.GetWindowThreadProcessId.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
    hwnd = user32.GetForegroundWindow()
    pid = ctypes.c_ulong()
    if not hwnd:
        return ""
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    if not pid.value:
        return ""
    kernel32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_bool, ctypes.c_ulong]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid.value)
    if not handle:
        return f"pid:{pid.value}"
    try:
        kernel32.QueryFullProcessImageNameW.argtypes = [
            ctypes.c_void_p,
            ctypes.c_ulong,
            ctypes.c_wchar_p,
            ctypes.POINTER(ctypes.c_ulong),
        ]
        size = ctypes.c_ulong(1024)
        buffer = ctypes.create_unicode_buffer(size.value)
        ok = kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size))
        if not ok:
            return f"pid:{pid.value}"
        return Path(buffer.value).stem
    finally:
        kernel32.CloseHandle(handle)


def lock_workstation() -> bool:
    user32.LockWorkStation.restype = ctypes.c_bool
    return bool(user32.LockWorkStation())


def is_locked_like(desktop: str, foreground: str) -> bool:
    foreground_lower = foreground.lower()
    return desktop == "Winlogon" or foreground_lower == "logonui" or (
        desktop != "Default" and foreground_lower == "lockapp"
    )


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def _parse_clock(value: object, default: str) -> tuple[int, int]:
    text = str(value or default)
    try:
        hour_text, minute_text = text.split(":", 1)
        hour = max(0, min(23, int(hour_text)))
        minute = max(0, min(59, int(minute_text)))
        return hour, minute
    except Exception:
        hour_text, minute_text = default.split(":", 1)
        return int(hour_text), int(minute_text)


def unlock_camera_config(pc_config: dict) -> dict:
    config = dict(DEFAULT_UNLOCK_CAMERA_ALERT)
    user_config = pc_config.get("unlock_camera_alert")
    if isinstance(user_config, dict):
        config.update(user_config)
    return config


def unlock_camera_disabled_now(config: dict, now: datetime | None = None) -> bool:
    now = now or datetime.now().astimezone()
    if config.get("disabled_weekdays_only", True) and now.weekday() >= 5:
        return False
    start_h, start_m = _parse_clock(config.get("disabled_start"), "09:00")
    end_h, end_m = _parse_clock(config.get("disabled_end"), "18:00")
    current = now.hour * 60 + now.minute
    start = start_h * 60 + start_m
    end = end_h * 60 + end_m
    if start <= end:
        return start <= current < end
    return current >= start or current < end


def capture_webcam_photo(photo_dir: Path, camera_index: int = 0, delay_seconds: float = 1.5) -> Path:
    try:
        import cv2
    except Exception as exc:
        raise RuntimeError("opencv-python is not installed; run: python -m pip install opencv-python") from exc

    photo_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
    path = photo_dir / f"unlock-{stamp}.jpg"
    camera = cv2.VideoCapture(int(camera_index), cv2.CAP_DSHOW)
    if not camera.isOpened():
        camera.release()
        raise RuntimeError(f"camera {camera_index} could not be opened")
    try:
        deadline = time.monotonic() + max(0.5, float(delay_seconds))
        frame = None
        while time.monotonic() < deadline:
            ok, candidate = camera.read()
            if ok and candidate is not None:
                frame = candidate
            time.sleep(0.1)
        if frame is None:
            ok, frame = camera.read()
        if frame is None:
            raise RuntimeError("camera returned no frame")
        ok = cv2.imwrite(str(path), frame, [int(cv2.IMWRITE_JPEG_QUALITY), 88])
        if not ok or not path.exists():
            raise RuntimeError("failed to save camera photo")
        return path
    finally:
        camera.release()


def format_unlock_camera_status(pc_config: dict) -> str:
    config = unlock_camera_config(pc_config)
    enabled = bool(config.get("enabled", True))
    disabled_now = unlock_camera_disabled_now(config)
    start = str(config.get("disabled_start", "09:00"))
    end = str(config.get("disabled_end", "18:00"))
    lines = [
        "\u89e3\u9501\u62cd\u7167\uff1a" + ("\u5df2\u5f00\u542f" if enabled else "\u5df2\u5173\u95ed"),
        f"\u5de5\u4f5c\u65e5\u514d\u6253\u6270\uff1a{start}-{end}",
        "\u5f53\u524d\u72b6\u6001\uff1a" + ("\u4f11\u7720\u65f6\u6bb5\uff0c\u4e0d\u62cd\u7167" if disabled_now else "\u975e\u5de5\u4f5c\u65f6\u6bb5\uff0c\u89e3\u9501\u4f1a\u62cd\u7167\u9884\u8b66"),
        f"\u6444\u50cf\u5934\uff1a{config.get('camera_index', 0)}",
    ]
    return "\n".join(lines)


def local_status_snapshot(pc_config_path: Path) -> dict:
    pc_config = read_json(pc_config_path)
    desktop = get_input_desktop_name()
    foreground = get_foreground_process_name()
    locked_like = is_locked_like(desktop, foreground)
    state_path = pc_config_path.with_name("pc_guard_session_state.json")
    try:
        saved_state = read_json(state_path)
    except Exception:
        saved_state = {}
    last_heartbeat = parse_iso(saved_state.get("agent_time"))
    heartbeat_age = None
    if last_heartbeat:
        heartbeat_age = max(0, int((datetime.now().astimezone() - last_heartbeat).total_seconds()))
    online = heartbeat_age is not None and heartbeat_age <= int(pc_config.get("stale_after_seconds", 120))
    saved_win_l = saved_state.get("win_l") or {}
    return {
        "now": iso_now(),
        "online": online,
        "sleep_like": not online,
        "heartbeat_age_seconds": heartbeat_age,
        "last_heartbeat": saved_state.get("agent_time"),
        "state": {
            "pc_name": socket.gethostname(),
            "agent_time": iso_now(),
            "input_desktop": desktop,
            "foreground_process": foreground,
            "locked_like": locked_like,
            "win_l": {
                "enabled": bool(saved_win_l.get("enabled", True)),
                "ready": bool(saved_win_l.get("ready", False)),
                "error": str(saved_win_l.get("error") or ""),
                "last_win_l_at": saved_win_l.get("last_win_l_at"),
                "seconds_since_last_win_l": saved_win_l.get("seconds_since_last_win_l"),
            },
        },
        "pending_command": None,
        "last_command_result": None,
    }


def extract_text(msg: dict) -> str:
    for item in msg.get("item_list") or []:
        if item.get("type") == TEXT:
            return str((item.get("text_item") or {}).get("text") or "").strip()
    return ""


def _short_local_time(value: object) -> str:
    parsed = parse_iso(value)
    if not parsed:
        return "\u672a\u77e5"
    local = parsed.astimezone()
    now = datetime.now().astimezone()
    if local.date() == now.date():
        return local.strftime("\u4eca\u5929 %H:%M")
    return local.strftime("%m\u6708%d\u65e5 %H:%M")


def format_status(data: dict) -> str:
    state = data.get("state") or {}
    win_l = state.get("win_l") or {}
    if not data.get("online"):
        return "\n".join(
            [
                "\u7535\u8111\u72b6\u6001\uff1a\u65e0\u6cd5\u786e\u8ba4",
                "\u7535\u8111\u53ef\u80fd\u6b63\u5728\u4f11\u7720\u3001\u5173\u673a\u6216\u65ad\u7f51\u3002",
                f"\u6700\u540e\u68c0\u67e5\uff1a{_short_local_time(data.get('last_heartbeat'))}",
            ]
        )
    if state.get("locked_like"):
        return "\n".join(
            [
                "\u7535\u8111\u72b6\u6001\uff1a\u5df2\u9501\u5c4f",
                "\u7535\u8111\u76ee\u524d\u5904\u4e8e\u9501\u5c4f\u754c\u9762\u3002",
                f"\u6700\u8fd1\u68c0\u67e5\uff1a{_short_local_time(data.get('now'))}",
            ]
        )
    lines = [
        "\u7535\u8111\u72b6\u6001\uff1a\u672a\u9501\u5c4f",
        "\u7535\u8111\u5f53\u524d\u53ef\u76f4\u63a5\u4f7f\u7528\u3002",
        "\u5efa\u8bae\uff1a\u79bb\u5f00\u7535\u8111\u524d\u53d1\u9001\u201c\u9501\u5c4f\u201d\u6216\u6309 Win+L\u3002",
    ]
    if win_l.get("last_win_l_at"):
        lines.append(f"\u6700\u8fd1 Win+L\uff1a{_short_local_time(win_l.get('last_win_l_at'))}")
    return "\n".join(lines)


def handle_command(text: str, pc_config_path: Path, security: SecurityMonitor) -> str | None:
    trimmed = text.strip()
    lower = trimmed.lower()
    if trimmed == "\u72b6\u6001" or lower in {"/pcstatus", "status"}:
        return format_status(local_status_snapshot(pc_config_path))
    if trimmed == "\u9501\u5c4f" or lower in {"/pclock", "lock"}:
        ok = lock_workstation()
        return "\u5df2\u8bf7\u6c42\u7535\u8111\u9501\u5c4f" if ok else "\u9501\u5c4f\u5931\u8d25\uff1aLockWorkStation returned false"
    if trimmed in {"\u5b89\u5168\u72b6\u6001", "\u5b89\u5168"} or lower in {"/secstatus", "/security"}:
        return format_security_status(security.run_scan())
    if trimmed in {"\u5b89\u5168\u4e8b\u4ef6", "\u98ce\u9669"} or lower in {"/secevents", "/events"}:
        scan = security.run_scan()
        return format_security_events(security.list_events(limit=8), status=scan)
    if trimmed in {"\u5f00\u653e\u7aef\u53e3", "\u7aef\u53e3"} or lower in {"/secports", "/ports"}:
        return format_security_ports(security.run_scan())
    if trimmed in {"\u7f51\u7edc\u5b89\u5168", "\u7f51\u7edc"} or lower in {"/secnet", "/network"}:
        return format_security_network(security.run_scan())
    if trimmed in {"\u9632\u62a4", "\u9694\u79bb", "\u52a0\u56fa"} or lower in {"/protect", "/harden"}:
        protection = apply_network_protection()
        scan = security.run_scan()
        return format_network_protection(protection, status=scan)
    if trimmed in {"\u89e3\u9501\u62cd\u7167", "\u9632\u76d7\u72b6\u6001", "\u9632\u76d7"} or lower in {"/unlockphoto", "/theft"}:
        return format_unlock_camera_status(read_json(pc_config_path))
    if trimmed == "\u5e2e\u52a9" or lower in {"/pchelp", "help"}:
        return (
            "\u5e38\u7528\u64cd\u4f5c\uff1a\n"
            "\u72b6\u6001 - \u67e5\u770b\u662f\u5426\u9501\u5c4f\n"
            "\u5b89\u5168 - \u67e5\u770b\u7535\u8111\u662f\u5426\u6709\u98ce\u9669\n"
            "\u7f51\u7edc - \u67e5\u770b\u5f53\u524d WiFi \u662f\u5426\u5b89\u5168\n"
            "\u98ce\u9669 - \u67e5\u770b\u6700\u8fd1\u53d1\u73b0\u7684\u95ee\u9898\n"
            "\u9632\u62a4 - \u52a0\u56fa\u7535\u8111\u4fa7\u7f51\u7edc\u66b4\u9732\n"
            "\u9632\u76d7 - \u67e5\u770b\u89e3\u9501\u62cd\u7167\u72b6\u6001\n"
            "\u9501\u5c4f - \u7acb\u5373\u9501\u5b9a\u7535\u8111\n\n"
            "\u5e73\u65f6\u53ea\u9700\u8981\u53d1\u9001\u201c\u72b6\u6001\u201d\u6216\u201c\u5b89\u5168\u201d\u3002"
        )
    return None


def maybe_send_unlock_camera_alert(
    pc_config_path: Path,
    base_url: str,
    token: str,
    account_id: str,
    allow_user: str,
) -> None:
    pc_config = read_json(pc_config_path)
    config = unlock_camera_config(pc_config)
    if not config.get("enabled", True):
        return
    state_path = pc_config_path.with_name("unlock_camera_state.json")
    try:
        monitor_state = read_json(state_path)
    except Exception:
        monitor_state = {}

    snapshot = local_status_snapshot(pc_config_path)
    pc_state = snapshot.get("state") or {}
    locked = bool(pc_state.get("locked_like"))
    now = datetime.now().astimezone()
    disabled_now = unlock_camera_disabled_now(config, now)
    previous_locked = bool(monitor_state.get("previous_locked_like"))

    if locked:
        monitor_state.update({"previous_locked_like": True, "last_locked_at": iso_now(), "updated_at": iso_now()})
        write_json(state_path, monitor_state)
        return

    if not previous_locked:
        monitor_state.update({"previous_locked_like": False, "updated_at": iso_now()})
        write_json(state_path, monitor_state)
        return

    last_alert = parse_iso(monitor_state.get("last_alert_at"))
    cooldown = max(60, int(config.get("cooldown_seconds", 300)))
    in_cooldown = bool(last_alert and (now - last_alert.astimezone()).total_seconds() < cooldown)
    monitor_state.update({"previous_locked_like": False, "last_unlocked_at": iso_now(), "updated_at": iso_now()})
    write_json(state_path, monitor_state)

    if disabled_now or in_cooldown:
        return

    photo_dir = pc_config_path.parent / "unlock_photos"
    caption = "\n".join(
        [
            "\u3010PC Guard \u89e3\u9501\u9884\u8b66\u3011",
            "\u68c0\u6d4b\u5230\u7535\u8111\u4ece\u9501\u5c4f\u53d8\u4e3a\u5df2\u89e3\u9501\u3002",
            f"\u65f6\u95f4\uff1a{now.strftime('%Y-%m-%d %H:%M:%S')}",
            "\u975e\u5de5\u4f5c\u65f6\u6bb5\uff0c\u5df2\u5c1d\u8bd5\u4f7f\u7528\u524d\u7f6e\u6444\u50cf\u5934\u62cd\u7167\u3002",
        ]
    )
    try:
        photo_path = capture_webcam_photo(
            photo_dir,
            int(config.get("camera_index", 0)),
            float(config.get("capture_delay_seconds", 1.5)),
        )
        try:
            send_media_with_openclaw(account_id, allow_user, caption, photo_path)
        except Exception as exc:
            try:
                send_message(base_url, token, allow_user, caption + f"\n\u7167\u7247\u5df2\u4fdd\u5b58\uff1a{photo_path}\n\u53d1\u9001\u7167\u7247\u5931\u8d25\uff1a{exc}", None)
            except Exception as notify_exc:
                print(f"unlock text fallback send failed: {notify_exc}", flush=True)
            print(f"unlock photo media send failed: {exc}", flush=True)
        monitor_state["last_alert_at"] = iso_now()
        monitor_state["last_photo_path"] = str(photo_path)
        write_json(state_path, monitor_state)
    except Exception as exc:
        try:
            send_message(base_url, token, allow_user, caption + f"\n\u62cd\u7167\u5931\u8d25\uff1a{exc}", None)
        except Exception as notify_exc:
            print(f"unlock capture failure notification failed: {notify_exc}", flush=True)
        monitor_state["last_alert_at"] = iso_now()
        monitor_state["last_error"] = str(exc)
        write_json(state_path, monitor_state)


def safe_handle_command(text: str, pc_config_path: Path, security: SecurityMonitor) -> str | None:
    try:
        return handle_command(text, pc_config_path, security)
    except Exception as exc:
        print(f"command handling failed for text={text!r}: {exc}", flush=True)
        return "\u547d\u4ee4\u5df2\u6536\u5230\uff0c\u4f46\u7535\u8111\u6682\u65f6\u6ca1\u6709\u8fd4\u56de\u7ed3\u679c\u3002\n\u5efa\u8bae\uff1a\u7a0d\u540e\u518d\u8bd5\u4e00\u6b21\u3002"


def reminder_message(pc_config_path: Path) -> str:
    snapshot = local_status_snapshot(pc_config_path)
    state = snapshot.get("state") or {}
    win_l = state.get("win_l") or {}
    last_win_l = parse_iso(win_l.get("last_win_l_at"))
    today = datetime.now().astimezone().date()
    locked_today = bool(last_win_l and last_win_l.astimezone().date() == today)
    if locked_today or state.get("locked_like"):
        result = "\u4eca\u5929\u5df2\u68c0\u6d4b\u5230\u9501\u5c4f\u64cd\u4f5c\uff0c\u65e0\u9700\u5904\u7406\u3002"
    else:
        result = "\u4eca\u5929\u8fd8\u6ca1\u6709\u68c0\u6d4b\u5230\u9501\u5c4f\u3002\n\u8bf7\u6309 Win+L\uff0c\u6216\u56de\u590d\u201c\u9501\u5c4f\u201d\u3002"
    return "\u4e0b\u73ed\u9501\u5c4f\u63d0\u9192\n" + result


def maybe_send_reminder(
    base_url: str,
    token: str,
    allow_user: str,
    pc_config_path: Path,
    reminder_state_path: Path,
) -> None:
    config = read_json(pc_config_path)
    reminder = config.get("reminder") or {}
    if not reminder.get("enabled", True):
        return
    now = datetime.now().astimezone()
    if reminder.get("weekdays_only", True) and now.weekday() >= 5:
        return
    hour, minute = [int(part) for part in str(reminder.get("time", "18:30")).split(":", 1)]
    target_minutes = hour * 60 + minute
    now_minutes = now.hour * 60 + now.minute
    late_window_minutes = max(5, int(reminder.get("late_window_minutes", 330)))
    if not target_minutes <= now_minutes <= min(1439, target_minutes + late_window_minutes):
        return
    try:
        sent_state = read_json(reminder_state_path)
    except Exception:
        sent_state = {}
    today = now.date().isoformat()
    if sent_state.get("last_sent_date") == today:
        return
    send_message(base_url, token, allow_user, reminder_message(pc_config_path), None)
    write_json(reminder_state_path, {"last_sent_date": today, "sent_at": iso_now()})
    print(f"sent 18:30 lock reminder to={allow_user}", flush=True)


def flush_security_alerts(
    security: SecurityMonitor,
    base_url: str,
    token: str,
    allow_user: str,
) -> None:
    delivered = []
    for alert in security.pop_alerts(limit=5):
        alert_id = str(alert.get("id") or "")
        message = "\u3010PC Guard \u9884\u8b66\u3011\n" + format_security_events([alert], limit=1)
        try:
            send_message(base_url, token, allow_user, message, None)
            if alert_id:
                delivered.append(alert_id)
            print(f"sent security alert id={alert_id} to={allow_user}", flush=True)
        except Exception as exc:
            print(f"security alert send failed id={alert_id}: {exc}", flush=True)
            break
    if delivered:
        security.ack_alerts(delivered)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pc-config", default="pc_guard_config.json")
    parser.add_argument("--openclaw-dir", default=str(Path.home() / ".openclaw"))
    parser.add_argument("--account")
    args = parser.parse_args()

    pc_config_path = Path(args.pc_config)
    pc_config = read_json(pc_config_path)
    security = SecurityMonitor(pc_config_path.parent)
    stop_competing_openclaw_gateway()
    account_id, account = find_account(Path(args.openclaw_dir), args.account)
    token = account["token"]
    base_url = account.get("baseUrl") or "https://ilinkai.weixin.qq.com"
    allow_user = account.get("userId") or ""
    if not allow_user:
        raise RuntimeError("Weixin account has no bound owner userId; refusing to start without an allowlist")
    sync_path = pc_config_path.with_name(f"weixin_direct_{account_id}.sync.json")
    reminder_state_path = pc_config_path.with_name("weixin_reminder_state.json")
    try:
        sync = read_json(sync_path)
    except Exception:
        sync = {"get_updates_buf": ""}

    print(
        f"PC Guard direct Weixin bot started: account={account_id} allowed_user={allow_user or '*'}",
        flush=True,
    )
    last_security_scan = 0.0
    while True:
        try:
            now_mono = time.monotonic()
            scan_interval = max(30, int((pc_config.get("security") or {}).get("scan_interval_seconds", 60)))
            if now_mono - last_security_scan >= scan_interval:
                security.run_scan()
                last_security_scan = now_mono
            flush_security_alerts(security, base_url, token, allow_user)
            maybe_send_unlock_camera_alert(pc_config_path, base_url, token, account_id, allow_user)
            maybe_send_reminder(base_url, token, allow_user, pc_config_path, reminder_state_path)
            resp = get_updates(base_url, token, sync.get("get_updates_buf") or "")
            ret = resp.get("ret")
            errcode = resp.get("errcode")
            if ret not in (None, 0) or errcode not in (None, 0):
                print(
                    f"getupdates returned ret={ret} errcode={errcode} errmsg={resp.get('errmsg')}",
                    flush=True,
                )
            if resp.get("get_updates_buf"):
                sync["get_updates_buf"] = resp.get("get_updates_buf")
                write_json(sync_path, sync)
            msgs = resp.get("msgs") or []
            if msgs:
                print(f"received {len(msgs)} message(s)", flush=True)
            for msg in msgs:
                from_user = msg.get("from_user_id") or ""
                text = extract_text(msg)
                print(f"inbound from={from_user} text={text!r}", flush=True)
                if from_user != allow_user:
                    print(f"rejected unauthorized sender={from_user}", flush=True)
                    continue
                reply = safe_handle_command(text, pc_config_path, security)
                if reply:
                    try:
                        send_message(base_url, token, from_user, reply, msg.get("context_token"))
                        print(f"sent reply to={from_user} text={text!r}", flush=True)
                    except Exception as exc:
                        print(f"send reply failed to={from_user} text={text!r}: {exc}", flush=True)
        except (TimeoutError, urllib.error.URLError) as exc:
            print(f"poll network error: {exc}", flush=True)
            time.sleep(3)
        except Exception as exc:
            print(f"poll error: {exc}", flush=True)
            time.sleep(5)


if __name__ == "__main__":
    main()
