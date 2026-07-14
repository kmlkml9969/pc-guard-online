$startup = [Environment]::GetFolderPath("Startup")
$root = Split-Path -Parent $MyInvocation.MyCommand.Path

$serverTarget = Join-Path $startup "PC Guard Server.cmd"
$agentTarget = Join-Path $startup "PC Guard Agent.cmd"
$gatewayTarget = Join-Path $startup "PC Guard Weixin Bot.cmd"
$oldGatewayTarget = Join-Path $startup "OpenClaw Gateway.cmd"

Copy-Item -LiteralPath (Join-Path $root "start_pc_guard_server.cmd") -Destination $serverTarget -Force
Copy-Item -LiteralPath (Join-Path $root "start_pc_guard_agent.cmd") -Destination $agentTarget -Force
Copy-Item -LiteralPath (Join-Path $root "start_openclaw_gateway.cmd") -Destination $gatewayTarget -Force
Remove-Item -LiteralPath $oldGatewayTarget -Force -ErrorAction SilentlyContinue

Write-Output "Installed startup launchers:"
Write-Output $serverTarget
Write-Output $agentTarget
Write-Output $gatewayTarget
