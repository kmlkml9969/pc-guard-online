param(
  [string]$InstallDir = "$env:LOCALAPPDATA\PCGuard",
  [switch]$WithWeixin
)

$ErrorActionPreference = "Stop"
$sourceDir = Split-Path -Parent $MyInvocation.MyCommand.Path

function Require-Command($name, $hint) {
  if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
    throw "$name not found. $hint"
  }
}

function Stop-OpenClawGateway {
  $openclawCmd = Join-Path $env:APPDATA "npm\openclaw.cmd"
  if (Test-Path -LiteralPath $openclawCmd) {
    try {
      & $openclawCmd gateway stop | Out-Host
      Start-Sleep -Seconds 2
    } catch {
      Write-Output "openclaw gateway stop failed, will check port 18789 directly."
    }
  }

  try {
    $listeners = @(Get-NetTCPConnection -LocalPort 18789 -State Listen -ErrorAction SilentlyContinue)
    foreach ($listener in $listeners) {
      $ownerProcessId = [int]$listener.OwningProcess
      if ($ownerProcessId -and $ownerProcessId -ne $PID) {
        $proc = Get-Process -Id $ownerProcessId -ErrorAction SilentlyContinue
        if ($proc -and ($proc.ProcessName -match "node|openclaw")) {
          Write-Output "Stopping stale OpenClaw Gateway process: pid=$ownerProcessId name=$($proc.ProcessName)"
          Stop-Process -Id $ownerProcessId -Force -ErrorAction SilentlyContinue
        }
      }
    }
  } catch {
    Write-Output "Could not inspect port 18789: $($_.Exception.Message)"
  }
}

function Start-OpenClawGateway {
  $openclawCmd = Join-Path $env:APPDATA "npm\openclaw.cmd"
  if (-not (Test-Path -LiteralPath $openclawCmd)) {
    throw "openclaw.cmd not found: $openclawCmd"
  }
  Stop-OpenClawGateway
  Start-Process -FilePath $openclawCmd -ArgumentList @("gateway", "--force") -WorkingDirectory $InstallDir -WindowStyle Hidden
  Start-Sleep -Seconds 5
  $listener = Get-NetTCPConnection -LocalPort 18789 -State Listen -ErrorAction SilentlyContinue
  if ($listener) {
    Write-Output "OpenClaw Gateway is listening on port 18789."
  } else {
    Write-Output "OpenClaw Gateway was started, but port 18789 is not listening yet. Try: openclaw gateway restart"
  }
}

function Stop-PCGuardWeixinDirect {
  try {
    $processes = @(Get-CimInstance Win32_Process -Filter "name = 'python.exe'" -ErrorAction SilentlyContinue | Where-Object {
      $_.CommandLine -like "*pc_guard_weixin_direct.py*"
    })
    foreach ($process in $processes) {
      Write-Output "Stopping old PC Guard direct Weixin bot process: pid=$($process.ProcessId)"
      Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
    }
  } catch {
    Write-Output "Could not inspect old PC Guard direct Weixin bot process: $($_.Exception.Message)"
  }
}

Require-Command python "Install Python 3.11+ first, or add it to PATH."

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

$files = @(
  "pc_guard_server.py",
  "pc_guard_agent.py",
  "pc_guard_weixin_direct.py",
  "weixin_qr_poll_save.py",
  "install_pc_guard_startup.ps1",
  "patch_openclaw_weixin_pcguard.ps1"
)

foreach ($file in $files) {
  Copy-Item -LiteralPath (Join-Path $sourceDir $file) -Destination (Join-Path $InstallDir $file) -Force
}

$tokenBytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($tokenBytes)
$token = [Convert]::ToBase64String($tokenBytes).TrimEnd("=").Replace("+", "-").Replace("/", "_")

$serverConfigPath = Join-Path $InstallDir "pc_guard_config.json"
$agentConfigPath = Join-Path $InstallDir "pc_guard_agent_config.json"

$serverConfig = @{
  bind_host = "127.0.0.1"
  bind_port = 8787
  timezone = "Asia/Shanghai"
  shared_token = $token
  stale_after_seconds = 120
  reminder = @{
    enabled = $true
    weekdays_only = $true
    time = "18:30"
    window_seconds = 300
  }
  notifications = @{
    ntfy_url = ""
    bark_url = ""
    wecom_webhook = ""
  }
  personal_wechat_bot = @{
    enabled = $false
    inbound_token = ""
    send_url = ""
    send_token = ""
    default_to = ""
  }
  openclaw_weixin = @{
    enabled = $false
    channel = "openclaw-weixin"
    account = ""
    target = ""
    openclaw_cmd = (Join-Path $env:APPDATA "npm\openclaw.cmd")
  }
}

$agentConfig = @{
  server_url = "http://127.0.0.1:8787"
  shared_token = $token
  pc_name = $env:COMPUTERNAME
  heartbeat_interval_seconds = 8
  enable_win_l_hook = $true
}

$serverConfig | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $serverConfigPath -Encoding UTF8
$agentConfig | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $agentConfigPath -Encoding UTF8

$serverLauncher = @'
@echo off
cd /d "%~dp0"
python "%~dp0pc_guard_server.py" --config "%~dp0pc_guard_config.json" >> "%~dp0pc_guard_server.log" 2>> "%~dp0pc_guard_server.err.log"
'@
$agentLauncher = @'
@echo off
cd /d "%~dp0"
python "%~dp0pc_guard_agent.py" --config "%~dp0pc_guard_agent_config.json" >> "%~dp0pc_guard_agent.log" 2>> "%~dp0pc_guard_agent.err.log"
'@
$gatewayLauncher = @'
@echo off
cd /d "%~dp0"
python "%~dp0pc_guard_weixin_direct.py" --pc-config "%~dp0pc_guard_config.json" >> "%~dp0weixin_direct.log" 2>> "%~dp0weixin_direct.err.log"
'@
Set-Content -LiteralPath (Join-Path $InstallDir "start_pc_guard_server.cmd") -Value $serverLauncher -Encoding ASCII
Set-Content -LiteralPath (Join-Path $InstallDir "start_pc_guard_agent.cmd") -Value $agentLauncher -Encoding ASCII
Set-Content -LiteralPath (Join-Path $InstallDir "start_openclaw_gateway.cmd") -Value $gatewayLauncher -Encoding ASCII

& (Join-Path $InstallDir "install_pc_guard_startup.ps1")

Start-Process -FilePath "python" -ArgumentList @("`"$InstallDir\pc_guard_server.py`"", "--config", "`"$serverConfigPath`"") -WorkingDirectory $InstallDir -WindowStyle Hidden
Start-Sleep -Seconds 2
Start-Process -FilePath "python" -ArgumentList @("`"$InstallDir\pc_guard_agent.py`"", "--config", "`"$agentConfigPath`"") -WorkingDirectory $InstallDir -WindowStyle Hidden

if ($WithWeixin) {
  $qrResponse = Invoke-RestMethod -Uri "https://ilinkai.weixin.qq.com/ilink/bot/get_bot_qrcode?bot_type=3" -Method Get -TimeoutSec 30
  Write-Output ""
  Write-Output "Scan this Weixin ClawBot authorization link with WeChat:"
  Write-Output $qrResponse.qrcode_img_content
  Start-Process $qrResponse.qrcode_img_content

  python (Join-Path $InstallDir "weixin_qr_poll_save.py") --qrcode $qrResponse.qrcode --timeout-seconds 480

  $accountsPath = Join-Path $env:USERPROFILE ".openclaw\openclaw-weixin\accounts.json"
  $accounts = Get-Content -LiteralPath $accountsPath -Raw | ConvertFrom-Json
  $account = @($accounts)[-1]
  $accountFile = Join-Path $env:USERPROFILE ".openclaw\openclaw-weixin\accounts\$account.json"
  $accountData = Get-Content -LiteralPath $accountFile -Raw | ConvertFrom-Json

  $serverConfig = Get-Content -LiteralPath $serverConfigPath -Raw | ConvertFrom-Json
  $serverConfig.openclaw_weixin.enabled = $true
  $serverConfig.openclaw_weixin.account = $account
  $serverConfig.openclaw_weixin.target = $accountData.userId
  $serverConfig | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $serverConfigPath -Encoding UTF8

  Stop-OpenClawGateway
  Stop-PCGuardWeixinDirect
  Start-Process -FilePath (Join-Path $InstallDir "start_openclaw_gateway.cmd") -WorkingDirectory $InstallDir -WindowStyle Hidden
  Write-Output "PC Guard direct Weixin bot started. OpenClaw Gateway is not required for PC Guard commands."
}

Write-Output ""
Write-Output "PC Guard installed."
Write-Output "InstallDir: $InstallDir"
if ($WithWeixin) {
  Write-Output "WeChat commands after setup: /pcstatus, /pclock, /pchelp. Chinese aliases are also enabled."
} else {
  Write-Output "Run again with -WithWeixin to connect the personal WeChat ClawBot plugin."
}
