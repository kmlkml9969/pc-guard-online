import argparse
import json
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


BASE_URL = "https://ilinkai.weixin.qq.com"


def normalize_account_id(raw: str) -> str:
    return raw.strip().lower().replace("@", "-").replace(".", "-").replace("/", "_").replace("\\", "_")


def get_json(url: str) -> dict:
    req = urllib.request.Request(url, method="GET")
    req.add_header("iLink-App-ClientVersion", "1")
    with urllib.request.urlopen(req, timeout=40) as response:
        return json.loads(response.read().decode("utf-8"))


def save_account(openclaw_dir: Path, account_id_raw: str, token: str, base_url: str, user_id: str) -> Path:
    account_id = normalize_account_id(account_id_raw)
    weixin_dir = openclaw_dir / "openclaw-weixin"
    accounts_dir = weixin_dir / "accounts"
    accounts_dir.mkdir(parents=True, exist_ok=True)

    data = {
        "token": token,
        "savedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "baseUrl": base_url or BASE_URL,
    }
    if user_id:
        data["userId"] = user_id

    account_path = accounts_dir / f"{account_id}.json"
    account_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    index_path = weixin_dir / "accounts.json"
    try:
        accounts = json.loads(index_path.read_text(encoding="utf-8"))
        if not isinstance(accounts, list):
            accounts = []
    except Exception:
        accounts = []
    if account_id not in accounts:
        accounts.append(account_id)
    index_path.write_text(json.dumps(accounts, ensure_ascii=False, indent=2), encoding="utf-8")

    if user_id:
        cred_dir = openclaw_dir / "credentials"
        cred_dir.mkdir(parents=True, exist_ok=True)
        allow_path = cred_dir / f"openclaw-weixin-{account_id}-allowFrom.json"
        allow = {"version": 1, "allowFrom": [user_id]}
        allow_path.write_text(json.dumps(allow, ensure_ascii=False, indent=2), encoding="utf-8")

    return account_path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--qrcode", required=True)
    parser.add_argument("--openclaw-dir", default=str(Path.home() / ".openclaw"))
    parser.add_argument("--timeout-seconds", type=int, default=480)
    args = parser.parse_args()

    qrcode = args.qrcode
    openclaw_dir = Path(args.openclaw_dir)
    deadline = time.time() + args.timeout_seconds
    print(f"Polling Weixin QR status for {args.timeout_seconds}s", flush=True)

    while time.time() < deadline:
        url = f"{BASE_URL}/ilink/bot/get_qrcode_status?qrcode={urllib.parse.quote(qrcode)}"
        status = get_json(url)
        print(json.dumps(status, ensure_ascii=False), flush=True)
        state = status.get("status")
        if state == "confirmed":
            account_id = status.get("ilink_bot_id") or ""
            token = status.get("bot_token") or ""
            base_url = status.get("baseurl") or BASE_URL
            user_id = status.get("ilink_user_id") or ""
            if not account_id or not token:
                raise RuntimeError("confirmed but account id or token missing")
            path = save_account(openclaw_dir, account_id, token, base_url, user_id)
            print(f"SAVED {path}", flush=True)
            return
        if state == "expired":
            print("EXPIRED", flush=True)
            return
        time.sleep(1)

    print("TIMEOUT", flush=True)


if __name__ == "__main__":
    main()
