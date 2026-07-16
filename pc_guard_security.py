"""Read-only Windows security snapshots and baseline change detection.

This module deliberately performs no remediation.  It collects system state with
PowerShell, compares later snapshots with the first successful baseline, and
persists events for a notification bridge to consume.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


STATE_FILE = "security_state.json"
EVENTS_FILE = "security_events.jsonl"
ALERT_QUEUE_FILE = "security_alert_queue.json"
STATE_VERSION = 1
MAX_EVENTS = 2000


POWERSHELL_SNAPSHOT = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding

$result = [ordered]@{
  collected_at = (Get-Date).ToUniversalTime().ToString('o')
  computer_name = $env:COMPUTERNAME
  firewall = @()
  network_profiles = @()
  wifi = @()
  gateways = @()
  dns = @()
  proxy = [ordered]@{}
  listeners = @()
  remote_control_processes = @()
  services = @()
  rdp_enabled = $false
  errors = @()
}

function Add-CollectionError([string]$section, [object]$errorRecord) {
  $result.errors += [ordered]@{ section = $section; message = [string]$errorRecord.Exception.Message }
}

try {
  $result.firewall = @(Get-NetFirewallProfile | ForEach-Object {
    [ordered]@{
      name = [string]$_.Name
      enabled = [bool]$_.Enabled
      default_inbound = [string]$_.DefaultInboundAction
      default_outbound = [string]$_.DefaultOutboundAction
    }
  })
} catch { Add-CollectionError 'firewall' $_ }

try {
  $result.network_profiles = @(Get-NetConnectionProfile | ForEach-Object {
    [ordered]@{
      name = [string]$_.Name
      interface_alias = [string]$_.InterfaceAlias
      interface_index = [int]$_.InterfaceIndex
      category = [string]$_.NetworkCategory
      ipv4_connectivity = [string]$_.IPv4Connectivity
      ipv6_connectivity = [string]$_.IPv6Connectivity
    }
  })
} catch { Add-CollectionError 'network_profiles' $_ }

try {
  $wlanText = (& netsh.exe wlan show interfaces 2>$null | Out-String)
  $blocks = $wlanText -split '(?:\r?\n){2,}'
  foreach ($block in $blocks) {
    $ssidMatch = [regex]::Match($block, '(?im)^\s*SSID\s*:\s*(.+?)\s*$')
    $bssidMatch = [regex]::Match($block, '(?im)^\s*(?:AP\s+)?BSSID\s*:\s*([0-9a-f:-]{17})\s*$')
    if ($ssidMatch.Success -or $bssidMatch.Success) {
      $result.wifi += [ordered]@{
        ssid = if ($ssidMatch.Success) { $ssidMatch.Groups[1].Value.Trim() } else { '' }
        bssid = if ($bssidMatch.Success) { $bssidMatch.Groups[1].Value.ToUpper() } else { '' }
      }
    }
  }
} catch { Add-CollectionError 'wifi' $_ }

try {
  foreach ($cfg in @(Get-NetIPConfiguration)) {
    foreach ($gateway in @($cfg.IPv4DefaultGateway)) {
      if ($null -eq $gateway -or [string]::IsNullOrWhiteSpace([string]$gateway.NextHop)) { continue }
      $mac = ''
      try {
        $neighbor = Get-NetNeighbor -InterfaceIndex $cfg.InterfaceIndex -IPAddress $gateway.NextHop -ErrorAction Stop | Select-Object -First 1
        if ($neighbor) { $mac = [string]$neighbor.LinkLayerAddress }
      } catch {}
      $result.gateways += [ordered]@{
        interface_alias = [string]$cfg.InterfaceAlias
        interface_index = [int]$cfg.InterfaceIndex
        ip = [string]$gateway.NextHop
        mac = $mac.ToUpper()
      }
    }
  }
} catch { Add-CollectionError 'gateways' $_ }

try {
  $activeAliases = @(Get-NetConnectionProfile | Select-Object -ExpandProperty InterfaceAlias)
  $result.dns = @(Get-DnsClientServerAddress | Where-Object {
    $_.ServerAddresses.Count -gt 0 -and $activeAliases -contains $_.InterfaceAlias
  } | ForEach-Object {
    [ordered]@{
      interface_alias = [string]$_.InterfaceAlias
      interface_index = [int]$_.InterfaceIndex
      address_family = [string]$_.AddressFamily
      servers = @($_.ServerAddresses | ForEach-Object { [string]$_ })
    }
  })
} catch { Add-CollectionError 'dns' $_ }

try {
  $internetSettings = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
  $winHttp = (& netsh.exe winhttp show proxy 2>$null | Out-String).Trim()
  $result.proxy = [ordered]@{
    enabled = [bool]($internetSettings.ProxyEnable -eq 1)
    server = [string]$internetSettings.ProxyServer
    override = [string]$internetSettings.ProxyOverride
    auto_config_url = [string]$internetSettings.AutoConfigURL
    auto_detect = [bool]($internetSettings.AutoDetect -eq 1)
    winhttp = $winHttp
  }
} catch { Add-CollectionError 'proxy' $_ }

try {
  $processCache = @{}
  $result.listeners = @(Get-NetTCPConnection -State Listen | Where-Object {
    $_.LocalAddress -notin @('127.0.0.1', '::1')
  } | ForEach-Object {
    $pidValue = [int]$_.OwningProcess
    if (-not $processCache.ContainsKey($pidValue)) {
      try {
        $p = Get-Process -Id $pidValue -ErrorAction Stop
        $processCache[$pidValue] = [ordered]@{ name = [string]$p.ProcessName; path = [string]$p.Path }
      } catch {
        $processCache[$pidValue] = [ordered]@{ name = ''; path = '' }
      }
    }
    [ordered]@{
      protocol = 'TCP'
      address = [string]$_.LocalAddress
      port = [int]$_.LocalPort
      pid = $pidValue
      process_name = [string]$processCache[$pidValue].name
      process_path = [string]$processCache[$pidValue].path
    }
  } | Sort-Object address, port, process_name)
} catch { Add-CollectionError 'listeners' $_ }

try {
  $knownRemoteNames = @(
    'anydesk','teamviewer','teamviewer_service','rustdesk','todesk','todesk_service',
    'todesk_session','sunloginclient',
    'sunloginclient.exe','orayremote','tvnserver','winvnc','vncserver','ultravnc',
    'screenconnect.clientservice','connectwisecontrol.client','remotepcservice',
    'splashtopstreamer','dwagent','aeroadmin','ammyy_admin','parsec','nomachine'
  )
  $result.remote_control_processes = @(Get-Process | Where-Object {
    $knownRemoteNames -contains $_.ProcessName.ToLowerInvariant()
  } | ForEach-Object {
    $path = ''
    try { $path = [string]$_.Path } catch {}
    [ordered]@{ name = [string]$_.ProcessName; pid = [int]$_.Id; path = $path }
  } | Sort-Object name, path)
} catch { Add-CollectionError 'remote_control_processes' $_ }

try {
  $serviceNames = @('TermService','WinRM','RemoteRegistry','LanmanServer')
  $result.services = @(Get-CimInstance Win32_Service | Where-Object { $_.Name -in $serviceNames } | ForEach-Object {
    [ordered]@{
      name = [string]$_.Name
      display_name = [string]$_.DisplayName
      state = [string]$_.State
      start_mode = [string]$_.StartMode
    }
  } | Sort-Object name)
  $rdpValue = Get-ItemPropertyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction Stop
  $result.rdp_enabled = [bool]($rdpValue -eq 0)
} catch { Add-CollectionError 'services_or_rdp' $_ }

$result | ConvertTo-Json -Depth 8 -Compress
"""


def _utc_now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _json_key(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _fingerprint(kind: str, subject: Any) -> str:
    payload = f"{kind}\0{_json_key(subject)}".encode("utf-8", errors="replace")
    return hashlib.sha256(payload).hexdigest()


def _read_json(path: Path, default: Any) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError, TypeError):
        return default


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _atomic_write_json(path: Path, value: Any) -> None:
    _atomic_write_text(path, json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def _decode_output(raw: bytes) -> str:
    for encoding in ("utf-8-sig", "utf-16", "gb18030", "mbcs"):
        try:
            return raw.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", errors="replace")


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _normalize_snapshot(raw: dict[str, Any]) -> dict[str, Any]:
    snapshot = dict(raw) if isinstance(raw, dict) else {}
    for key in (
        "firewall",
        "network_profiles",
        "wifi",
        "gateways",
        "dns",
        "listeners",
        "remote_control_processes",
        "services",
        "errors",
    ):
        snapshot[key] = _as_list(snapshot.get(key))
    snapshot["proxy"] = snapshot.get("proxy") if isinstance(snapshot.get("proxy"), dict) else {}
    snapshot["rdp_enabled"] = bool(snapshot.get("rdp_enabled", False))
    snapshot.setdefault("collected_at", _utc_now())
    snapshot.setdefault("computer_name", os.environ.get("COMPUTERNAME", ""))
    return snapshot


def collect_security_snapshot(timeout: int = 35) -> dict[str, Any]:
    """Collect a read-only Windows snapshot using one PowerShell JSON response."""
    if os.name != "nt":
        return _normalize_snapshot({"errors": [{"section": "platform", "message": "Windows is required"}]})
    try:
        completed = subprocess.run(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "-"],
            input=POWERSHELL_SNAPSHOT.encode("ascii"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=max(5, int(timeout)),
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        output = _decode_output(completed.stdout).strip()
        if not output:
            message = _decode_output(completed.stderr).strip() or f"PowerShell exited with {completed.returncode}"
            return _normalize_snapshot({"errors": [{"section": "powershell", "message": message}]})
        try:
            return _normalize_snapshot(json.loads(output))
        except json.JSONDecodeError as exc:
            return _normalize_snapshot(
                {"errors": [{"section": "powershell_json", "message": f"{exc}: {output[-500:]}"}]}
            )
    except Exception as exc:
        return _normalize_snapshot({"errors": [{"section": "collector", "message": str(exc)}]})


def _items_by_key(items: Iterable[Any], keys: tuple[str, ...]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        identity = tuple(str(item.get(key, "")).lower() for key in keys)
        result[_json_key(identity)] = item
    return result


def _dns_identity(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    for item in snapshot.get("dns", []):
        if not isinstance(item, dict):
            continue
        result.append(
            {
                "interface_alias": str(item.get("interface_alias", "")),
                "address_family": str(item.get("address_family", "")),
                "servers": sorted(str(value) for value in _as_list(item.get("servers"))),
            }
        )
    return sorted(result, key=_json_key)


def _gateway_identity(snapshot: dict[str, Any]) -> list[dict[str, str]]:
    result = []
    for item in snapshot.get("gateways", []):
        if isinstance(item, dict):
            result.append(
                {
                    "interface_alias": str(item.get("interface_alias", "")),
                    "ip": str(item.get("ip", "")),
                    "mac": str(item.get("mac", "")).upper(),
                }
            )
    return sorted(result, key=_json_key)


def _proxy_identity(snapshot: dict[str, Any]) -> dict[str, Any]:
    proxy = snapshot.get("proxy", {})
    return {
        "enabled": bool(proxy.get("enabled", False)),
        "server": str(proxy.get("server", "")),
        "override": str(proxy.get("override", "")),
        "auto_config_url": str(proxy.get("auto_config_url", "")),
        "auto_detect": bool(proxy.get("auto_detect", False)),
        "winhttp": str(proxy.get("winhttp", "")).strip(),
    }


def _failed_sections(snapshot: dict[str, Any]) -> set[str]:
    failed = set()
    for item in snapshot.get("errors", []):
        if isinstance(item, dict):
            failed.add(str(item.get("section", "")))
    return failed


def _finding(kind: str, severity: str, title: str, detail: str, subject: Any) -> dict[str, Any]:
    return {
        "fingerprint": _fingerprint(kind, subject),
        "type": kind,
        "severity": severity,
        "title": title,
        "detail": detail,
        "subject": subject,
    }


def _find_baseline_differences(baseline: dict[str, Any], current: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    failed = _failed_sections(baseline) | _failed_sections(current)

    if "firewall" not in failed:
        baseline_firewall = _items_by_key(baseline.get("firewall", []), ("name",))
        for key, profile in _items_by_key(current.get("firewall", []), ("name",)).items():
            before = baseline_firewall.get(key)
            if before and bool(before.get("enabled", False)) and not bool(profile.get("enabled", False)):
                name = str(profile.get("name", "Unknown"))
                findings.append(_finding("firewall_disabled", "high", "Windows 防火墙已关闭", f"{name} 防火墙配置已从开启变为关闭。", {"profile": name}))

    if "services_or_rdp" not in failed and not bool(baseline.get("rdp_enabled")) and bool(current.get("rdp_enabled")):
        findings.append(_finding("rdp_enabled", "high", "远程桌面已开启", "Windows 远程桌面已从关闭变为开启。", {"rdp_enabled": True}))

    baseline_remote = _items_by_key(baseline.get("remote_control_processes", []), ("name", "path"))
    for key, process in _items_by_key(current.get("remote_control_processes", []), ("name", "path")).items():
        if key not in baseline_remote:
            subject = {"name": process.get("name", ""), "path": process.get("path", "")}
            findings.append(_finding("remote_control_process", "high", "发现常见远控程序", f"检测到 {subject['name']} 正在运行。", subject))

    baseline_listeners = _items_by_key(baseline.get("listeners", []), ("protocol", "address", "port", "process_name", "process_path"))
    for key, listener in _items_by_key(current.get("listeners", []), ("protocol", "address", "port", "process_name", "process_path")).items():
        if key not in baseline_listeners:
            subject = {
                "protocol": listener.get("protocol", "TCP"),
                "address": listener.get("address", ""),
                "port": listener.get("port", 0),
                "process_name": listener.get("process_name", ""),
                "process_path": listener.get("process_path", ""),
            }
            detail = f"{subject['process_name'] or '未知进程'} 新增监听 {subject['address']}:{subject['port']}。"
            findings.append(_finding("new_listener", "medium", "发现新的非回环监听端口", detail, subject))

    if "gateways" not in failed:
        old_gateway = _gateway_identity(baseline)
        new_gateway = _gateway_identity(current)
        if old_gateway != new_gateway:
            subject = {"baseline": old_gateway, "current": new_gateway}
            findings.append(_finding("gateway_changed", "high", "网关 IP 或 MAC 已变化", "默认网关身份与首次基线不同。", subject))

    if "dns" not in failed:
        old_dns = _dns_identity(baseline)
        new_dns = _dns_identity(current)
        if old_dns != new_dns:
            subject = {"baseline": old_dns, "current": new_dns}
            findings.append(_finding("dns_changed", "medium", "DNS 配置已变化", "DNS 服务器与首次基线不同。", subject))

    if "proxy" not in failed:
        old_proxy = _proxy_identity(baseline)
        new_proxy = _proxy_identity(current)
        if old_proxy != new_proxy:
            subject = {"baseline": old_proxy, "current": new_proxy}
            findings.append(_finding("proxy_changed", "medium", "系统代理已变化", "用户或 WinHTTP 代理与首次基线不同。", subject))

    return findings


class SecurityMonitor:
    """Persist security baselines, events, and an acknowledgement-based alert queue."""

    def __init__(self, data_dir: str | os.PathLike[str] | None = None, timeout: int = 35):
        self.data_dir = Path(data_dir or os.environ.get("PC_GUARD_DATA_DIR") or Path(__file__).resolve().parent)
        self.state_path = self.data_dir / STATE_FILE
        self.events_path = self.data_dir / EVENTS_FILE
        self.alert_queue_path = self.data_dir / ALERT_QUEUE_FILE
        self.timeout = timeout
        self._lock = threading.RLock()

    def _load_state(self) -> dict[str, Any]:
        value = _read_json(self.state_path, {})
        return value if isinstance(value, dict) else {}

    def _load_queue(self) -> list[dict[str, Any]]:
        value = _read_json(self.alert_queue_path, [])
        return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []

    def _write_events(self, new_events: list[dict[str, Any]]) -> None:
        if not new_events:
            return
        existing = self.list_events(limit=MAX_EVENTS)
        known_ids = {str(event.get("id", "")) for event in existing}
        combined = existing + [event for event in new_events if str(event.get("id", "")) not in known_ids]
        combined = combined[-MAX_EVENTS:]
        text = "".join(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n" for event in combined)
        _atomic_write_text(self.events_path, text)

    def run_scan(self) -> dict[str, Any]:
        """Collect one snapshot, update state, and enqueue newly active findings."""
        snapshot = collect_security_snapshot(self.timeout)
        with self._lock:
            state = self._load_state()
            baseline = state.get("baseline") if isinstance(state.get("baseline"), dict) else None
            collection_failed = bool(snapshot.get("errors")) and not any(
                snapshot.get(key) for key in ("firewall", "network_profiles", "gateways", "dns", "listeners", "services")
            )

            if baseline is None and not collection_failed:
                state = {
                    "version": STATE_VERSION,
                    "baseline_created_at": _utc_now(),
                    "baseline": snapshot,
                    "last_scan_at": _utc_now(),
                    "last_snapshot": snapshot,
                    "active_findings": {},
                }
                _atomic_write_json(self.state_path, state)
                if not self.alert_queue_path.exists():
                    _atomic_write_json(self.alert_queue_path, [])
                return {"ok": True, "baseline_created": True, "snapshot": snapshot, "new_events": [], "active_findings": []}

            if baseline is None:
                state.update({"version": STATE_VERSION, "last_scan_at": _utc_now(), "last_snapshot": snapshot})
                _atomic_write_json(self.state_path, state)
                return {"ok": False, "baseline_created": False, "snapshot": snapshot, "new_events": [], "active_findings": [], "errors": snapshot.get("errors", [])}

            findings = _find_baseline_differences(baseline, snapshot)
            previous_active = state.get("active_findings") if isinstance(state.get("active_findings"), dict) else {}
            active = {finding["fingerprint"]: finding for finding in findings}
            new_findings = [finding for finding in findings if finding["fingerprint"] not in previous_active]
            events = []
            for finding in new_findings:
                event = dict(finding)
                event.update({"id": uuid.uuid4().hex, "created_at": _utc_now(), "status": "active"})
                events.append(event)

            queue = self._load_queue()
            queued_fingerprints = {str(item.get("fingerprint", "")) for item in queue}
            queue.extend(event for event in events if event["fingerprint"] not in queued_fingerprints)
            self._write_events(events)
            _atomic_write_json(self.alert_queue_path, queue)
            state.update(
                {
                    "version": STATE_VERSION,
                    "last_scan_at": _utc_now(),
                    "last_snapshot": snapshot,
                    "active_findings": active,
                }
            )
            _atomic_write_json(self.state_path, state)
            return {
                "ok": not collection_failed,
                "baseline_created": False,
                "snapshot": snapshot,
                "new_events": events,
                "active_findings": findings,
                "errors": snapshot.get("errors", []),
            }

    def list_events(self, limit: int = 20) -> list[dict[str, Any]]:
        """Return the newest persisted events, oldest-to-newest within the slice."""
        try:
            lines = self.events_path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        events = []
        for line in lines:
            try:
                value = json.loads(line)
                if isinstance(value, dict):
                    events.append(value)
            except (ValueError, TypeError):
                continue
        return events[-max(0, int(limit)) :] if limit else []

    def pop_alerts(self, limit: int = 20) -> list[dict[str, Any]]:
        """Return pending alerts without deleting them; call ack_alerts after delivery."""
        with self._lock:
            return self._load_queue()[: max(0, int(limit))]

    def ack_alerts(self, alert_ids: Iterable[str] | str | None = None) -> int:
        """Acknowledge delivered alerts.  None acknowledges all pending alerts."""
        with self._lock:
            queue = self._load_queue()
            if alert_ids is None:
                removed = len(queue)
                remaining: list[dict[str, Any]] = []
            else:
                if isinstance(alert_ids, str):
                    wanted = {alert_ids}
                else:
                    wanted = {str(value) for value in alert_ids}
                remaining = [item for item in queue if str(item.get("id", "")) not in wanted]
                removed = len(queue) - len(remaining)
            _atomic_write_json(self.alert_queue_path, remaining)
            return removed


def _find_baseline_differences(baseline: dict[str, Any], current: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    failed = _failed_sections(baseline) | _failed_sections(current)

    if "firewall" not in failed:
        baseline_firewall = _items_by_key(baseline.get("firewall", []), ("name",))
        for key, profile in _items_by_key(current.get("firewall", []), ("name",)).items():
            before = baseline_firewall.get(key)
            if before and bool(before.get("enabled", False)) and not bool(profile.get("enabled", False)):
                name = str(profile.get("name", "Unknown"))
                findings.append(
                    _finding(
                        "firewall_disabled",
                        "high",
                        "Windows \u9632\u706b\u5899\u5df2\u5173\u95ed",
                        f"{name} \u9632\u706b\u5899\u914d\u7f6e\u5df2\u4ece\u5f00\u542f\u53d8\u4e3a\u5173\u95ed\u3002",
                        {"profile": name},
                    )
                )

    if "services_or_rdp" not in failed and not bool(baseline.get("rdp_enabled")) and bool(current.get("rdp_enabled")):
        findings.append(
            _finding(
                "rdp_enabled",
                "high",
                "\u8fdc\u7a0b\u684c\u9762\u5df2\u5f00\u542f",
                "Windows \u8fdc\u7a0b\u684c\u9762\u5df2\u4ece\u5173\u95ed\u53d8\u4e3a\u5f00\u542f\u3002",
                {"rdp_enabled": True},
            )
        )

    baseline_profiles = _items_by_key(baseline.get("network_profiles", []), ("interface_alias", "name"))
    for key, profile in _items_by_key(current.get("network_profiles", []), ("interface_alias", "name")).items():
        before = baseline_profiles.get(key)
        if before and str(before.get("category", "")).lower() == "public" and str(profile.get("category", "")).lower() != "public":
            subject = {"name": profile.get("name", ""), "category": profile.get("category", "")}
            findings.append(
                _finding(
                    "network_profile_changed",
                    "medium",
                    "\u7f51\u7edc\u5df2\u79bb\u5f00\u516c\u7528\u7f51\u7edc\u6a21\u5f0f",
                    "\u5c40\u57df\u7f51\u5165\u7ad9\u89c4\u5219\u53ef\u80fd\u56e0\u7f51\u7edc\u5206\u7c7b\u53d8\u5316\u800c\u653e\u5bbd\u3002",
                    subject,
                )
            )

    baseline_remote = _items_by_key(baseline.get("remote_control_processes", []), ("name", "path"))
    for key, process in _items_by_key(current.get("remote_control_processes", []), ("name", "path")).items():
        if key not in baseline_remote:
            subject = {"name": process.get("name", ""), "path": process.get("path", "")}
            findings.append(
                _finding(
                    "remote_control_process",
                    "high",
                    "\u53d1\u73b0\u5e38\u89c1\u8fdc\u63a7\u7a0b\u5e8f",
                    f"\u68c0\u6d4b\u5230 {subject['name']} \u6b63\u5728\u8fd0\u884c\u3002",
                    subject,
                )
            )

    listener_keys = ("protocol", "address", "port", "process_name", "process_path")
    baseline_listeners = _items_by_key(baseline.get("listeners", []), listener_keys)
    for key, listener in _items_by_key(current.get("listeners", []), listener_keys).items():
        if key not in baseline_listeners:
            subject = {
                "protocol": listener.get("protocol", "TCP"),
                "address": listener.get("address", ""),
                "port": listener.get("port", 0),
                "process_name": listener.get("process_name", ""),
                "process_path": listener.get("process_path", ""),
            }
            process_name = subject["process_name"] or "\u672a\u77e5\u8fdb\u7a0b"
            findings.append(
                _finding(
                    "new_listener",
                    "medium",
                    "\u53d1\u73b0\u65b0\u7684\u975e\u56de\u73af\u76d1\u542c\u7aef\u53e3",
                    f"{process_name} \u65b0\u589e\u76d1\u542c {subject['address']}:{subject['port']}\u3002",
                    subject,
                )
            )

    if "gateways" not in failed:
        old_gateway = _gateway_identity(baseline)
        new_gateway = _gateway_identity(current)
        if old_gateway != new_gateway:
            subject = {"baseline": old_gateway, "current": new_gateway}
            findings.append(
                _finding(
                    "gateway_changed",
                    "high",
                    "\u7f51\u5173 IP \u6216 MAC \u5df2\u53d8\u5316",
                    "\u9ed8\u8ba4\u7f51\u5173\u8eab\u4efd\u4e0e\u9996\u6b21\u57fa\u7ebf\u4e0d\u540c\u3002",
                    subject,
                )
            )

    if "dns" not in failed:
        old_dns = _dns_identity(baseline)
        new_dns = _dns_identity(current)
        if old_dns != new_dns:
            subject = {"baseline": old_dns, "current": new_dns}
            findings.append(
                _finding(
                    "dns_changed",
                    "medium",
                    "DNS \u914d\u7f6e\u5df2\u53d8\u5316",
                    "DNS \u670d\u52a1\u5668\u4e0e\u9996\u6b21\u57fa\u7ebf\u4e0d\u540c\u3002",
                    subject,
                )
            )

    if "proxy" not in failed:
        old_proxy = _proxy_identity(baseline)
        new_proxy = _proxy_identity(current)
        if old_proxy != new_proxy:
            subject = {"baseline": old_proxy, "current": new_proxy}
            findings.append(
                _finding(
                    "proxy_changed",
                    "medium",
                    "\u7cfb\u7edf\u4ee3\u7406\u5df2\u53d8\u5316",
                    "\u7528\u6237\u6216 WinHTTP \u4ee3\u7406\u4e0e\u9996\u6b21\u57fa\u7ebf\u4e0d\u540c\u3002",
                    subject,
                )
            )

    return findings


def _snapshot_from(value: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    nested = value.get("snapshot")
    return nested if isinstance(nested, dict) else value


def format_security_status(value: dict[str, Any] | None) -> str:
    snapshot = _snapshot_from(value)
    firewalls = snapshot.get("firewall", [])
    disabled = [str(item.get("name", "未知")) for item in firewalls if isinstance(item, dict) and not item.get("enabled")]
    remote = snapshot.get("remote_control_processes", [])
    errors = snapshot.get("errors", [])
    lines = [
        "电脑安全状态",
        f"检查时间：{snapshot.get('collected_at', '未知')}",
        f"防火墙：{'存在关闭配置：' + ', '.join(disabled) if disabled else '已开启'}",
        f"远程桌面：{'已开启' if snapshot.get('rdp_enabled') else '未开启'}",
        f"常见远控进程：{len(remote)} 个",
        f"非回环监听端口：{len(snapshot.get('listeners', []))} 个",
    ]
    if errors:
        lines.append(f"采集警告：{len(errors)} 项")
    return "\n".join(lines)


def format_security_events(events: Iterable[dict[str, Any]], limit: int = 10) -> str:
    selected = list(events)[-max(0, int(limit)) :]
    if not selected:
        return "暂无安全事件。"
    lines = ["最近安全事件"]
    for event in reversed(selected):
        lines.append(f"[{event.get('severity', 'info')}] {event.get('title', event.get('type', '事件'))}")
        lines.append(f"{event.get('created_at', '')} {event.get('detail', '')}".strip())
        lines.append(f"事件号：{event.get('id', '未知')}")
    return "\n".join(lines)


def format_security_ports(value: dict[str, Any] | None, limit: int = 30) -> str:
    snapshot = _snapshot_from(value)
    listeners = snapshot.get("listeners", [])
    if not listeners:
        return "未发现非回环 TCP 监听端口。"
    lines = [f"非回环 TCP 监听端口（{len(listeners)} 个）"]
    for item in listeners[: max(0, int(limit))]:
        lines.append(f"{item.get('address', '')}:{item.get('port', '')}  {item.get('process_name') or '未知进程'} (PID {item.get('pid', '?')})")
    if len(listeners) > limit:
        lines.append(f"另有 {len(listeners) - limit} 个未显示。")
    return "\n".join(lines)


def format_security_network(value: dict[str, Any] | None) -> str:
    snapshot = _snapshot_from(value)
    wifi = snapshot.get("wifi", [])
    gateways = snapshot.get("gateways", [])
    dns = _dns_identity(snapshot)
    proxy = _proxy_identity(snapshot)
    lines = ["网络安全状态"]
    if wifi:
        for item in wifi:
            lines.append(f"WiFi：{item.get('ssid') or '未知'}  BSSID：{item.get('bssid') or '未知'}")
    else:
        lines.append("WiFi：未连接或无法读取")
    for item in gateways:
        lines.append(f"网关：{item.get('ip') or '未知'}  MAC：{item.get('mac') or '未知'}")
    dns_servers = sorted({server for item in dns for server in item.get("servers", [])})
    lines.append(f"DNS：{', '.join(dns_servers) if dns_servers else '未知'}")
    proxy_text = proxy.get("server") or proxy.get("auto_config_url") or ("已配置 WinHTTP" if proxy.get("winhttp") else "未启用")
    lines.append(f"系统代理：{proxy_text}")
    profiles = snapshot.get("network_profiles", [])
    for profile in profiles:
        lines.append(f"网络分类：{profile.get('name') or profile.get('interface_alias')} / {profile.get('category', '未知')}")
    return "\n".join(lines)


def format_security_status(value: dict[str, Any] | None) -> str:
    snapshot = _snapshot_from(value)
    firewalls = snapshot.get("firewall", [])
    disabled = [
        str(item.get("name", "unknown"))
        for item in firewalls
        if isinstance(item, dict) and not item.get("enabled")
    ]
    remote = snapshot.get("remote_control_processes", [])
    errors = snapshot.get("errors", [])
    firewall_text = "\u5df2\u5f00\u542f" if not disabled else "\u5b58\u5728\u5173\u95ed\u914d\u7f6e\uff1a" + ", ".join(disabled)
    rdp_text = "\u5df2\u5f00\u542f" if snapshot.get("rdp_enabled") else "\u672a\u5f00\u542f"
    lines = [
        "\u7535\u8111\u5b89\u5168\u72b6\u6001",
        f"\u68c0\u67e5\u65f6\u95f4\uff1a{snapshot.get('collected_at', '\u672a\u77e5')}",
        f"\u9632\u706b\u5899\uff1a{firewall_text}",
        f"\u8fdc\u7a0b\u684c\u9762\uff1a{rdp_text}",
        f"\u5e38\u89c1\u8fdc\u63a7\u8fdb\u7a0b\uff1a{len(remote)} \u4e2a",
        f"\u975e\u56de\u73af\u76d1\u542c\u7aef\u53e3\uff1a{len(snapshot.get('listeners', []))} \u4e2a",
    ]
    if errors:
        lines.append(f"\u91c7\u96c6\u8b66\u544a\uff1a{len(errors)} \u9879")
    return "\n".join(lines)


def format_security_events(events: Iterable[dict[str, Any]], limit: int = 10) -> str:
    selected = list(events)[-max(0, int(limit)) :]
    if not selected:
        return "\u6682\u65e0\u5b89\u5168\u4e8b\u4ef6\u3002"
    lines = ["\u6700\u8fd1\u5b89\u5168\u4e8b\u4ef6"]
    for event in reversed(selected):
        lines.append(f"[{event.get('severity', 'info')}] {event.get('title', event.get('type', '\u4e8b\u4ef6'))}")
        lines.append(f"{event.get('created_at', '')} {event.get('detail', '')}".strip())
        lines.append(f"\u4e8b\u4ef6\u53f7\uff1a{event.get('id', '\u672a\u77e5')}")
    return "\n".join(lines)


def format_security_ports(value: dict[str, Any] | None, limit: int = 30) -> str:
    snapshot = _snapshot_from(value)
    listeners = snapshot.get("listeners", [])
    if not listeners:
        return "\u672a\u53d1\u73b0\u975e\u56de\u73af TCP \u76d1\u542c\u7aef\u53e3\u3002"
    lines = [f"\u975e\u56de\u73af TCP \u76d1\u542c\u7aef\u53e3\uff08{len(listeners)} \u4e2a\uff09"]
    for item in listeners[: max(0, int(limit))]:
        process_name = item.get("process_name") or "\u672a\u77e5\u8fdb\u7a0b"
        lines.append(f"{item.get('address', '')}:{item.get('port', '')}  {process_name} (PID {item.get('pid', '?')})")
    if len(listeners) > limit:
        lines.append(f"\u53e6\u6709 {len(listeners) - limit} \u4e2a\u672a\u663e\u793a\u3002")
    return "\n".join(lines)


def format_security_network(value: dict[str, Any] | None) -> str:
    snapshot = _snapshot_from(value)
    wifi = snapshot.get("wifi", [])
    gateways = snapshot.get("gateways", [])
    dns = _dns_identity(snapshot)
    proxy = _proxy_identity(snapshot)
    lines = ["\u7f51\u7edc\u5b89\u5168\u72b6\u6001"]
    if wifi:
        for item in wifi:
            lines.append(f"WiFi\uff1a{item.get('ssid') or '\u672a\u77e5'}  BSSID\uff1a{item.get('bssid') or '\u672a\u77e5'}")
    else:
        lines.append("WiFi\uff1a\u672a\u8fde\u63a5\u6216\u65e0\u6cd5\u8bfb\u53d6")
    for item in gateways:
        lines.append(f"\u7f51\u5173\uff1a{item.get('ip') or '\u672a\u77e5'}  MAC\uff1a{item.get('mac') or '\u672a\u77e5'}")
    dns_servers = sorted({server for item in dns for server in item.get("servers", [])})
    lines.append(f"DNS\uff1a{', '.join(dns_servers) if dns_servers else '\u672a\u77e5'}")
    proxy_text = proxy.get("server") or proxy.get("auto_config_url")
    if not proxy_text:
        proxy_text = "\u5df2\u914d\u7f6e WinHTTP" if proxy.get("winhttp") else "\u672a\u542f\u7528"
    lines.append(f"\u7cfb\u7edf\u4ee3\u7406\uff1a{proxy_text}")
    for profile in snapshot.get("network_profiles", []):
        name = profile.get("name") or profile.get("interface_alias")
        lines.append(f"\u7f51\u7edc\u5206\u7c7b\uff1a{name} / {profile.get('category', '\u672a\u77e5')}")
    return "\n".join(lines)


__all__ = [
    "SecurityMonitor",
    "collect_security_snapshot",
    "format_security_status",
    "format_security_events",
    "format_security_ports",
    "format_security_network",
]
