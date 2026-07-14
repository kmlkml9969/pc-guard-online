param(
  [string]$PluginDir = "$env:USERPROFILE\.openclaw\extensions\openclaw-weixin",
  [string]$PcGuardConfigPath = "$env:LOCALAPPDATA\PCGuard\pc_guard_config.json"
)

$ErrorActionPreference = "Stop"

$messagingDir = Join-Path $PluginDir "src\messaging"
$slashPath = Join-Path $messagingDir "slash-commands.ts"
$processPath = Join-Path $messagingDir "process-message.ts"

if (-not (Test-Path -LiteralPath $messagingDir)) {
  throw "OpenClaw Weixin plugin messaging directory not found: $messagingDir"
}
if (-not (Test-Path -LiteralPath $processPath)) {
  throw "process-message.ts not found: $processPath"
}

$slashCommands = @'
import fs from "node:fs";
import http from "node:http";

import type { WeixinApiOptions } from "../api/api.js";
import { logger } from "../util/logger.js";

import { toggleDebugMode } from "./debug-mode.js";
import { sendMessageWeixin } from "./send.js";

export interface SlashCommandResult {
  handled: boolean;
}

export interface SlashCommandContext {
  to: string;
  contextToken?: string;
  baseUrl: string;
  token?: string;
  accountId: string;
  log: (msg: string) => void;
  errLog: (msg: string) => void;
}

async function sendReply(ctx: SlashCommandContext, text: string): Promise<void> {
  const opts: WeixinApiOptions & { contextToken?: string } = {
    baseUrl: ctx.baseUrl,
    token: ctx.token,
    contextToken: ctx.contextToken,
  };
  await sendMessageWeixin({ to: ctx.to, text, opts });
}

async function handleEcho(
  ctx: SlashCommandContext,
  args: string,
  receivedAt: number,
  eventTimestamp?: number,
): Promise<void> {
  const message = args.trim();
  if (message) {
    await sendReply(ctx, message);
  }
  const eventTs = eventTimestamp ?? 0;
  const platformDelay = eventTs > 0 ? `${receivedAt - eventTs}ms` : "N/A";
  await sendReply(
    ctx,
    [
      "Channel timing",
      `event: ${eventTs > 0 ? new Date(eventTs).toISOString() : "N/A"}`,
      `platform_to_plugin: ${platformDelay}`,
      `plugin_handling: ${Date.now() - receivedAt}ms`,
    ].join("\n"),
  );
}

type PcGuardConfig = {
  baseUrl: string;
  token: string;
};

function loadPcGuardConfig(): PcGuardConfig {
  const configPath =
    process.env.PC_GUARD_CONFIG ||
    "__PC_GUARD_CONFIG_PATH__";
  let baseUrl = process.env.PC_GUARD_URL || "http://127.0.0.1:8787";
  let token = process.env.PC_GUARD_TOKEN || "";
  try {
    const raw = fs.readFileSync(configPath, "utf-8").replace(/^\uFEFF/, "");
    const parsed = JSON.parse(raw);
    baseUrl = String(parsed.base_url || parsed.baseUrl || baseUrl).replace(/\/+$/, "");
    token = String(parsed.shared_token || token);
  } catch {
    // Fall back to environment/defaults.
  }
  if (!token) {
    throw new Error("PC Guard token is missing");
  }
  return { baseUrl, token };
}

function localHttpJson(url: URL, method: string): Promise<any> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: url.hostname,
        port: url.port,
        path: `${url.pathname}${url.search}`,
        method,
        timeout: 5000,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf-8");
          if ((res.statusCode ?? 500) < 200 || (res.statusCode ?? 500) >= 300) {
            reject(new Error(`PC Guard HTTP ${res.statusCode}: ${text.slice(0, 200)}`));
            return;
          }
          try {
            resolve(JSON.parse(text));
          } catch (err) {
            reject(new Error(`PC Guard invalid JSON: ${String(err)} body=${text.slice(0, 200)}`));
          }
        });
      },
    );
    req.on("timeout", () => req.destroy(new Error("PC Guard request timeout")));
    req.on("error", reject);
    req.end();
  });
}

async function pcGuardApi(path: string, method = "GET"): Promise<any> {
  const cfg = loadPcGuardConfig();
  const url = new URL(path, cfg.baseUrl);
  url.searchParams.set("token", cfg.token);
  return await localHttpJson(url, method);
}

function zh(key: string): string {
  const map: Record<string, string> = {
    offline: "\u79bb\u7ebf/\u7591\u4f3c\u4f11\u7720\u3001\u5173\u673a\u6216\u65ad\u7f51",
    locked: "\u5df2\u9501\u5c4f\u6216\u5904\u4e8e\u9501\u5c4f\u754c\u9762",
    unlocked: "\u672a\u9501\u5c4f",
    pcState: "\u7535\u8111\u72b6\u6001",
    lastHeartbeat: "\u6700\u540e\u5fc3\u8df3",
    heartbeatAge: "\u5fc3\u8df3\u5e74\u9f84",
    lastWinL: "\u6700\u8fd1 Win+L",
    foreground: "\u524d\u53f0\u8fdb\u7a0b",
    serverTime: "\u670d\u52a1\u5668\u65f6\u95f4",
    none: "\u65e0",
    unknown: "\u672a\u77e5",
    notCaptured: "\u672a\u6355\u83b7",
  };
  return map[key] || key;
}

function formatPcGuardStatus(data: any): string {
  const state = data?.state || {};
  const winL = state?.win_l || {};
  let headline = zh("offline");
  if (data?.online) {
    headline = state?.locked_like ? zh("locked") : zh("unlocked");
  }
  return [
    `${zh("pcState")}\uff1a${headline}`,
    `${zh("lastHeartbeat")}\uff1a${data?.last_heartbeat || zh("none")}`,
    `${zh("heartbeatAge")}\uff1a${data?.heartbeat_age_seconds ?? zh("none")} \u79d2`,
    `${zh("lastWinL")}\uff1a${winL?.last_win_l_at || zh("notCaptured")}`,
    `${zh("foreground")}\uff1a${state?.foreground_process || zh("unknown")}`,
    `${zh("serverTime")}\uff1a${data?.now || zh("unknown")}`,
  ].join("\n");
}

async function handlePcStatus(ctx: SlashCommandContext): Promise<void> {
  await sendReply(ctx, formatPcGuardStatus(await pcGuardApi("/api/status")));
}

async function handlePcLock(ctx: SlashCommandContext): Promise<void> {
  const result = await pcGuardApi("/api/lock", "POST");
  const id = result?.queued?.id || "unknown";
  await sendReply(
    ctx,
    `\u5df2\u4e0b\u53d1\u9501\u5c4f\u547d\u4ee4\uff1a${id}\n\u7535\u8111\u5728\u7ebf\u65f6\u4f1a\u5728\u4e0b\u4e00\u6b21\u5fc3\u8df3\u6267\u884c\u3002`,
  );
}

async function handlePcHelp(ctx: SlashCommandContext): Promise<void> {
  await sendReply(
    ctx,
    [
      "\u53ef\u7528\u547d\u4ee4\uff1a",
      "\u72b6\u6001 \u6216 /pcstatus - \u67e5\u770b\u7535\u8111\u9501\u5c4f/\u4f11\u7720\u72b6\u6001",
      "\u9501\u5c4f \u6216 /pclock - \u8fdc\u7a0b\u9501\u5b9a\u7535\u8111",
      "\u5e2e\u52a9 \u6216 /pchelp - \u67e5\u770b\u547d\u4ee4",
    ].join("\n"),
  );
}

export async function handleSlashCommand(
  content: string,
  ctx: SlashCommandContext,
  receivedAt: number,
  eventTimestamp?: number,
): Promise<SlashCommandResult> {
  const trimmed = content.trim();
  const normalizedText =
    trimmed === "\u72b6\u6001" ? "/pcstatus" :
    trimmed === "\u9501\u5c4f" ? "/pclock" :
    trimmed === "\u5e2e\u52a9" ? "/pchelp" :
    trimmed;
  if (!normalizedText.startsWith("/")) {
    return { handled: false };
  }

  const spaceIdx = normalizedText.indexOf(" ");
  const command = spaceIdx === -1 ? normalizedText.toLowerCase() : normalizedText.slice(0, spaceIdx).toLowerCase();
  const args = spaceIdx === -1 ? "" : normalizedText.slice(spaceIdx + 1);

  logger.info(`[weixin] Slash command: ${command}, args: ${args.slice(0, 50)}`);

  try {
    switch (command) {
      case "/echo":
        await handleEcho(ctx, args, receivedAt, eventTimestamp);
        return { handled: true };
      case "/toggle-debug": {
        const enabled = toggleDebugMode(ctx.accountId);
        await sendReply(ctx, enabled ? "Debug mode enabled" : "Debug mode disabled");
        return { handled: true };
      }
      case "/pcstatus":
        await handlePcStatus(ctx);
        return { handled: true };
      case "/pclock":
        await handlePcLock(ctx);
        return { handled: true };
      case "/pchelp":
        await handlePcHelp(ctx);
        return { handled: true };
      default:
        return { handled: false };
    }
  } catch (err) {
    logger.error(`[weixin] Slash command error: ${String(err)}`);
    try {
      await sendReply(ctx, `\u547d\u4ee4\u6267\u884c\u5931\u8d25\uff1a${String(err).slice(0, 300)}`);
    } catch {
      // Ignore secondary send failures.
    }
    return { handled: true };
  }
}
'@

$pcGuardConfigLiteral = ConvertTo-Json -Compress $PcGuardConfigPath
$slashCommands = $slashCommands.Replace('"__PC_GUARD_CONFIG_PATH__"', $pcGuardConfigLiteral)
Set-Content -LiteralPath $slashPath -Value $slashCommands -Encoding UTF8

$processText = Get-Content -LiteralPath $processPath -Raw
$patched = $processText -replace 'if \(textBody\.startsWith\("/"\)\) \{', 'if (textBody.startsWith("/") || ["\u72b6\u6001", "\u9501\u5c4f", "\u5e2e\u52a9"].includes(textBody.trim())) {'
if ($patched -eq $processText -and $processText -notmatch '\\u72b6\\u6001') {
  throw "Could not patch process-message.ts command detector"
}
Set-Content -LiteralPath $processPath -Value $patched -Encoding UTF8

Write-Output "Patched OpenClaw Weixin plugin for PC Guard commands."
