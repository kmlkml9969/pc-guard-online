$ErrorActionPreference = "Stop"

$BaseUrl = $env:PC_GUARD_BASE_URL
if ([string]::IsNullOrWhiteSpace($BaseUrl)) {
  $BaseUrl = "https://raw.githubusercontent.com/kmlkml9969/pc-guard-online/pcguard-20260717-2"
}

$WithWeixin = $true
if ($env:PC_GUARD_WITH_WEIXIN -match "^(0|false|no)$") {
  $WithWeixin = $false
}

$SkipDependencyInstall = $false
if ($env:PC_GUARD_SKIP_DEPENDENCY_INSTALL -match "^(1|true|yes)$") {
  $SkipDependencyInstall = $true
}

function Refresh-Path {
  $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
  $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
  $env:Path = "$machinePath;$userPath"
}

function Ensure-Command {
  param(
    [string]$Name,
    [string]$WingetId
  )

  if (Get-Command $Name -ErrorAction SilentlyContinue) {
    return
  }
  if ($SkipDependencyInstall) {
    throw "$Name not found. Install it first or rerun without -SkipDependencyInstall."
  }
  if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    throw "$Name not found, and winget is unavailable for automatic install."
  }

  Write-Output "Installing dependency: $WingetId"
  winget install --id $WingetId --exact --accept-source-agreements --accept-package-agreements --scope user
  Refresh-Path

  if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
    throw "$Name still not found after installing $WingetId. Restart PowerShell and rerun this command."
  }
}

if ($BaseUrl -like "*YOUR_DOMAIN_OR_RAW_GITHUB_PATH*") {
  throw "Set -BaseUrl to the folder URL that hosts the PC Guard files."
}

Ensure-Command -Name "python" -WingetId "Python.Python.3.12"

$base = $BaseUrl.TrimEnd("/")
$work = Join-Path $env:TEMP ("pcguard-install-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $work | Out-Null

$files = @(
  "pc_guard_server.py",
  "pc_guard_agent.py",
  "pc_guard_security.py",
  "pc_guard_weixin_direct.py",
  "weixin_qr_poll_save.py",
  "install_pc_guard_startup.ps1",
  "patch_openclaw_weixin_pcguard.ps1",
  "install_pc_guard_one_command.ps1"
)

foreach ($file in $files) {
  $url = "$base/$file"
  $dest = Join-Path $work $file
  Write-Output "Downloading $file"
  Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing
}

$installer = Join-Path $work "install_pc_guard_one_command.ps1"
if ($WithWeixin) {
  powershell -NoProfile -ExecutionPolicy Bypass -File $installer -WithWeixin
} else {
  powershell -NoProfile -ExecutionPolicy Bypass -File $installer
}
