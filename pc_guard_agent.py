import argparse
import ctypes
import ctypes.wintypes
import json
import os
import socket
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Optional


DEFAULT_CONFIG = {
    "server_url": "",
    "shared_token": "CHANGE_ME_LONG_RANDOM_TOKEN",
    "pc_name": "",
    "heartbeat_interval_seconds": 8,
    "enable_win_l_hook": True,
    "local_state_path": "",
}


user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


VK_L = 0x4C
VK_LWIN = 0x5B
VK_RWIN = 0x5C
WM_KEYDOWN = 0x0100
WM_KEYUP = 0x0101
WM_SYSKEYDOWN = 0x0104
WM_SYSKEYUP = 0x0105
WH_KEYBOARD_LL = 13

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

last_win_l_at: Optional[str] = None
last_win_l_monotonic: Optional[float] = None
win_key_down = False
hook_ready = False
hook_error = ""
state_lock = threading.Lock()


class KBDLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [
        ("vkCode", ctypes.c_ulong),
        ("scanCode", ctypes.c_ulong),
        ("flags", ctypes.c_ulong),
        ("time", ctypes.c_ulong),
        ("dwExtraInfo", ctypes.c_ulonglong),
    ]


LowLevelKeyboardProc = ctypes.WINFUNCTYPE(
    ctypes.c_long,
    ctypes.c_int,
    ctypes.c_ulong,
    ctypes.POINTER(KBDLLHOOKSTRUCT),
)


def iso_now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def write_json_atomic(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(path.suffix + ".tmp")
    temp_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temp_path, path)


def load_config(path: str) -> dict:
    config = DEFAULT_CONFIG.copy()
    if path and Path(path).exists():
        raw = json.loads(Path(path).read_text(encoding="utf-8-sig"))
        config.update(raw)
    env_token = os.getenv("PC_GUARD_TOKEN")
    if env_token:
        config["shared_token"] = env_token
    if not config.get("pc_name"):
        config["pc_name"] = socket.gethostname()
    return config


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


@LowLevelKeyboardProc
def keyboard_proc(n_code, w_param, l_param):
    global win_key_down, last_win_l_at, last_win_l_monotonic
    if n_code == 0:
        vk = int(l_param.contents.vkCode)
        if w_param in (WM_KEYDOWN, WM_SYSKEYDOWN):
            if vk in (VK_LWIN, VK_RWIN):
                with state_lock:
                    win_key_down = True
            elif vk == VK_L:
                with state_lock:
                    if win_key_down:
                        last_win_l_at = iso_now()
                        last_win_l_monotonic = time.monotonic()
        elif w_param in (WM_KEYUP, WM_SYSKEYUP) and vk in (VK_LWIN, VK_RWIN):
            with state_lock:
                win_key_down = False
    return user32.CallNextHookEx(None, n_code, w_param, ctypes.cast(l_param, ctypes.c_void_p))


def keyboard_hook_loop() -> None:
    global hook_ready, hook_error
    kernel32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
    kernel32.GetModuleHandleW.restype = ctypes.c_void_p
    user32.CallNextHookEx.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_ulong, ctypes.c_void_p]
    user32.CallNextHookEx.restype = ctypes.c_long
    user32.SetWindowsHookExW.argtypes = [
        ctypes.c_int,
        LowLevelKeyboardProc,
        ctypes.c_void_p,
        ctypes.c_ulong,
    ]
    user32.SetWindowsHookExW.restype = ctypes.c_void_p
    user32.GetMessageW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint]
    module = kernel32.GetModuleHandleW(None)
    hook = user32.SetWindowsHookExW(WH_KEYBOARD_LL, keyboard_proc, module, 0)
    if not hook:
        hook_error = f"SetWindowsHookExW failed: {ctypes.get_last_error()}"
        return
    hook_ready = True
    msg = ctypes.wintypes.MSG()
    while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) != 0:
        user32.TranslateMessage(ctypes.byref(msg))
        user32.DispatchMessageW(ctypes.byref(msg))


def collect_status(config: dict) -> dict:
    desktop = get_input_desktop_name()
    foreground = get_foreground_process_name()
    with state_lock:
        last_hotkey = last_win_l_at
        seconds_since_hotkey = None
        if last_win_l_monotonic is not None:
            seconds_since_hotkey = int(time.monotonic() - last_win_l_monotonic)
        hook = {
            "enabled": bool(config.get("enable_win_l_hook", True)),
            "ready": hook_ready,
            "error": hook_error,
            "last_win_l_at": last_hotkey,
            "seconds_since_last_win_l": seconds_since_hotkey,
        }
    locked_like = desktop == "Winlogon" or foreground.lower() in ("lockapp", "logonui")
    return {
        "pc_name": config["pc_name"],
        "agent_time": iso_now(),
        "input_desktop": desktop,
        "foreground_process": foreground,
        "locked_like": locked_like,
        "win_l": hook,
    }


def post_json(url: str, token: str, payload: dict, timeout: int = 10) -> dict:
    raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=raw, method="POST")
    req.add_header("Content-Type", "application/json; charset=utf-8")
    req.add_header("X-PC-GUARD-TOKEN", token)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def command_result(config: dict, command: dict, ok: bool, message: str) -> None:
    payload = {
        "pc_name": config["pc_name"],
        "command": command,
        "ok": ok,
        "message": message,
        "finished_at": iso_now(),
    }
    try:
        post_json(
            config["server_url"].rstrip("/") + "/api/command_result",
            config["shared_token"],
            payload,
        )
    except Exception as exc:
        print(f"command result post failed: {exc}", flush=True)


def run_agent(config: dict, config_path: Path) -> None:
    if config.get("enable_win_l_hook", True):
        threading.Thread(target=keyboard_hook_loop, daemon=True).start()
    interval = max(3, int(config.get("heartbeat_interval_seconds", 8)))
    server_url = str(config.get("server_url") or "").rstrip("/")
    heartbeat_url = server_url + "/api/heartbeat" if server_url else ""
    configured_state_path = str(config.get("local_state_path") or "").strip()
    state_path = Path(configured_state_path) if configured_state_path else config_path.with_name("pc_guard_session_state.json")
    while True:
        status = collect_status(config)
        try:
            write_json_atomic(state_path, status)
        except OSError as exc:
            print(f"local state write failed: {exc}", flush=True)
        if heartbeat_url:
            try:
                response = post_json(heartbeat_url, config["shared_token"], status)
                command = response.get("command") or {}
                if command.get("action") == "lock":
                    ok = lock_workstation()
                    command_result(config, command, ok, "LockWorkStation called" if ok else "LockWorkStation failed")
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
                print(f"heartbeat failed: {exc}", flush=True)
        time.sleep(interval)


def main() -> None:
    parser = argparse.ArgumentParser(description="PC Guard Windows agent")
    parser.add_argument("--config", default="pc_guard_agent_config.json")
    args = parser.parse_args()
    config = load_config(args.config)
    print(f"PC Guard agent started for {config['pc_name']}", flush=True)
    run_agent(config, Path(args.config).resolve())


if __name__ == "__main__":
    main()
