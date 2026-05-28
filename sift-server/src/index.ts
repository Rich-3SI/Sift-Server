/**
 * sift-server CLI entrypoint.
 *
 *   sift-server --config ./config.json
 *
 * Boots:
 *   - Config loader + validation
 *   - ConfigStore (with optional Supabase sync)
 *   - Shared UpstreamPool (connects to all upstream MCP servers)
 *   - SiftServer (HTTP/StreamableHTTP firewall + per-session MCP servers)
 *   - Admin/health HTTP listener
 *   - Heartbeat to Supabase (when SUPABASE_URL + SIFT_ORG_ID are set)
 */

import { ConfigStore } from "../../src/config-store.js";
import {
  compositeAudit,
  consoleAudit,
  jsonlAudit,
  sqliteAudit,
  supabaseAudit,
  startSupabaseAuditFlushJob,
  webhookAudit,
  type AuditHandler,
} from "../../src/audit.js";
import { UpstreamPool } from "../../src/upstream-pool.js";
import { loadServerConfig, resolveServerOptions } from "./config.js";
import { SiftServer } from "./server.js";
import { startHealthServer } from "./health.js";
import { startServerHeartbeat } from "./heartbeat.js";

interface CliArgs {
  configPath: string;
  showHelp: boolean;
}

function parseArgs(argv: string[]): CliArgs {
  const out: CliArgs = { configPath: "sift-server.config.json", showHelp: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--config" || a === "-c") {
      out.configPath = argv[++i] ?? out.configPath;
    } else if (a === "--help" || a === "-h") {
      out.showHelp = true;
    }
  }
  return out;
}

function printHelp(): void {
  process.stdout.write(
    `sift-server — MCP security firewall for company-deployed MCP servers\n\n` +
      `Usage:\n` +
      `  sift-server --config <path/to/config.json>\n\n` +
      `Flags:\n` +
      `  -c, --config <path>   Path to sift-server.config.json (default: ./sift-server.config.json)\n` +
      `  -h, --help            Print this message and exit\n\n` +
      `Environment variables:\n` +
      `  SUPABASE_URL / SUPABASE_ANON_KEY   Enable cloud policy sync + audit + heartbeat\n` +
      `  SIFT_ORG_ID                        Required for enterprise features\n` +
      `  SIFT_DB_PATH                       Local SQLite audit path (default ~/.sift)\n` +
      `  SIFT_ADMIN_SECRET                  Required for admin mutation endpoints\n`
  );
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  if (args.showHelp) {
    printHelp();
    return;
  }

  const cfg = loadServerConfig(args.configPath);
  const opts = resolveServerOptions(cfg);

  // 1. Config store — resolves rules per user and optionally syncs from Supabase.
  const configStore = new ConfigStore(cfg);
  const dashboardIngestUrl = process.env["SIFT_DASHBOARD_INGEST_URL"] ?? process.env["SIFT_DASHBOARD_URL"];
  const ingestSecret = process.env["SIFT_INGEST_SECRET"];
  const supabaseUrl = process.env["SUPABASE_URL"];
  const supabaseKey = process.env["SUPABASE_ANON_KEY"];
  const orgId = process.env["SIFT_ORG_ID"];
  if (dashboardIngestUrl && ingestSecret) {
    configStore.startDashboardSync(dashboardIngestUrl, ingestSecret, 30_000);
    startSupabaseAuditFlushJob();
  } else if (supabaseUrl && supabaseKey) {
    configStore.startSupabaseSync(supabaseUrl, supabaseKey, 30_000, orgId);
    startSupabaseAuditFlushJob();
  } else {
    process.stderr.write(
      "[Sift Server] No enterprise backend credentials set — running with local config only.\n"
    );
  }

  // 2. Audit handlers — console + local SQLite; Supabase is only active when an entry
  //    carries an orgId (set from TenantContext during request handling).
  const auditHandlers: AuditHandler[] = [consoleAudit, sqliteAudit, supabaseAudit];
  if (cfg.audit?.jsonlPath) {
    auditHandlers.push(jsonlAudit(cfg.audit.jsonlPath));
  }
  for (const webhook of cfg.audit?.webhooks ?? []) {
    auditHandlers.push(webhookAudit(webhook));
  }
  const auditHandler = compositeAudit(...auditHandlers);

  // 3. Shared upstream pool — one connection pool for the whole server, reused
  //    across every incoming session.
  const pool = new UpstreamPool();
  await pool.connectAll(cfg.upstreams ?? []);

  // 4. Sift Server — HTTP/StreamableHTTP endpoint per MCP session.
  const server = new SiftServer({
    configStore,
    pool,
    auditHandler,
    options: opts,
  });
  await server.start();

  // 5. Health + admin HTTP listener.
  startHealthServer(opts.adminPort, pool, server, configStore);

  // 6. Heartbeat — reports live status + tool call counters to Supabase.
  const stopHeartbeat = startServerHeartbeat({
    pool,
    server,
    options: opts,
    orgId,
  });

  // 7. Graceful shutdown.
  const shutdown = async (): Promise<void> => {
    process.stderr.write("[Sift Server] Shutting down...\n");
    stopHeartbeat?.();
    await server.stop();
    await pool.closeAll();
    process.exit(0);
  };
  process.on("SIGINT", () => void shutdown());
  process.on("SIGTERM", () => void shutdown());
}

void main().catch((err: unknown) => {
  process.stderr.write(`[Sift Server] Fatal error: ${String(err)}\n`);
  process.exit(1);
});
