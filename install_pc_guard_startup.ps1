$startup = [Environment]::GetFolderPath("Startup")
$root = Split-Path -Parent $MyInvocation.MyCommand.Path

$agentTarget = Join-Path $startup "PC Guard Agent.cmd"
$gatewayTarget = Join-Path $startup "PC Guard Weixin Bot.cmd"
$oldGatewayTarget = Join-Path $startup "OpenClaw Gateway.cmd"
$oldServerTarget = Join-Path $startup "PC Guard Server.cmd"

$agentLauncher = @"
@echo off
call "$root\start_pc_guard_agent.cmd"
"@
$weixinLauncher = @"
@echo off
call "$root\start_openclaw_gateway.cmd"
"@

Set-Content -LiteralPath $agentTarget -Value $agentLauncher -Encoding ASCII
Set-Content -LiteralPath $gatewayTarget -Value $weixinLauncher -Encoding ASCII
Remove-Item -LiteralPath $oldGatewayTarget,$oldServerTarget -Force -ErrorAction SilentlyContinue

Write-Output "Installed startup launchers:"
Write-Output $agentTarget
Write-Output $gatewayTarget
