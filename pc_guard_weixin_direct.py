import argparse
import base64
import json
import random
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path


CHANNEL_VERSION = "1.0.3"
TEXT = 1
BOT = 2
FINISH = 2


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


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
        timeout=45,
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


def pc_api(config: dict, path: str, method: str = "GET") -> dict:
    base = f"http://{config.get('bind_host', '127.0.0.1')}:{int(config.get('bind_port', 8787))}"
    url = urllib.parse.urljoin(base, path)
    sep = "&" if "?" in url else "?"
    url = f"{url}{sep}token={urllib.parse.quote(str(config['shared_token']))}"
    req = urllib.request.Request(url, method=method)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def extract_text(msg: dict) -> str:
    for item in msg.get("item_list") or []:
        if item.get("type") == TEXT:
            return str((item.get("text_item") or {}).get("text") or "").strip()
    return ""


def format_status(data: dict) -> str:
    state = data.get("state") or {}
    win_l = state.get("win_l") or {}
    if not data.get("online"):
        headline = "\u79bb\u7ebf/\u7591\u4f3c\u4f11\u7720\u3001\u5173\u673a\u6216\u65ad\u7f51"
    elif state.get("locked_like"):
        headline = "\u5df2\u9501\u5c4f\u6216\u5904\u4e8e\u9501\u5c4f\u754c\u9762"
    else:
        headline = "\u672a\u9501\u5c4f"
    return "\n".join(
        [
            f"\u7535\u8111\u72b6\u6001\uff1a{headline}",
            "\u6700\u540e\u5fc3\u8df3\uff1a" + str(data.get("last_heartbeat") or "\u65e0"),
            "\u5fc3\u8df3\u5e74\u9f84\uff1a" + str(data.get("heartbeat_age_seconds", "\u65e0")) + " \u79d2",
            "\u6700\u8fd1 Win+L\uff1a" + str(win_l.get("last_win_l_at") or "\u672a\u6355\u83b7"),
            "\u524d\u53f0\u8fdb\u7a0b\uff1a" + str(state.get("foreground_process") or "\u672a\u77e5"),
            "\u670d\u52a1\u5668\u65f6\u95f4\uff1a" + str(data.get("now") or "\u672a\u77e5"),
        ]
    )


def handle_command(text: str, pc_config: dict) -> str | None:
    trimmed = text.strip()
    lower = trimmed.lower()
    if trimmed == "\u72b6\u6001" or lower in {"/pcstatus", "status"}:
        return format_status(pc_api(pc_config, "/api/status"))
    if trimmed == "\u9501\u5c4f" or lower in {"/pclock", "lock"}:
        result = pc_api(pc_config, "/api/lock", method="POST")
        queued = (result.get("queued") or {}).get("id") or "unknown"
        return "\u5df2\u4e0b\u53d1\u9501\u5c4f\u547d\u4ee4\uff1a" + str(queued)
    if trimmed == "\u5e2e\u52a9" or lower in {"/pchelp", "help"}:
        return "\u53ef\u7528\u547d\u4ee4\uff1a\n/pcstatus \u6216 \u72b6\u6001\n/pclock \u6216 \u9501\u5c4f\n/pchelp \u6216 \u5e2e\u52a9"
    return None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pc-config", default="pc_guard_config.json")
    parser.add_argument("--openclaw-dir", default=str(Path.home() / ".openclaw"))
    parser.add_argument("--account")
    args = parser.parse_args()

    pc_config_path = Path(args.pc_config)
    pc_config = read_json(pc_config_path)
    account_id, account = find_account(Path(args.openclaw_dir), args.account)
    token = account["token"]
    base_url = account.get("baseUrl") or "https://ilinkai.weixin.qq.com"
    allow_user = account.get("userId") or ""
    sync_path = pc_config_path.with_name(f"weixin_direct_{account_id}.sync.json")
    try:
        sync = read_json(sync_path)
    except Exception:
        sync = {"get_updates_buf": ""}

    print(
        f"PC Guard direct Weixin bot started: account={account_id} allowed_user={allow_user or '*'}",
        flush=True,
    )
    while True:
        try:
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
                reply = handle_command(text, pc_config)
                if reply:
                    send_message(base_url, token, from_user, reply, msg.get("context_token"))
                    print(f"handled command from={from_user} text={text!r}", flush=True)
        except (TimeoutError, urllib.error.URLError) as exc:
            print(f"poll network error: {exc}", flush=True)
            time.sleep(3)
        except Exception as exc:
            print(f"poll error: {exc}", flush=True)
            time.sleep(5)


if __name__ == "__main__":
    main()
