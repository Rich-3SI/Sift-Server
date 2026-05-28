/**
 * Heartbeat for Sift Server instances.
 *
 * Reports to Supabase table `sift_server_instances` every 60s so the cloud
 * dashboard can show which servers are online and how busy they are.
 *
 * Gated on SUPABASE_URL + SUPABASE_ANON_KEY + orgId — without those, this is
 * a noop (useful for local/dev runs).
 */

import { createClient } from "@supabase/supabase-js";
import { hostname as getHostname } from "node:os";
import { randomUUID } from "node:crypto";
import { getSupabaseUrl, getSupabaseAnonKey } from "../../src/sift-server.js";
import type { UpstreamPool } from "../../src/upstream-pool.js";
import type { SiftServer } from "./server.js";
import type { ResolvedServerOptions } from "./config.js";

export interface ServerHeartbeatOptions {
  pool: UpstreamPool;
  server: SiftServer;
  options: ResolvedServerOptions;
  orgId?: string;
  intervalMs?: number;
}

export function startServerHeartbeat(opts: ServerHeartbeatOptions): (() => void) | null {
  const dashboardUrl = process.env["SIFT_DASHBOARD_INGEST_URL"] ?? process.env["SIFT_DASHBOARD_URL"];
  const ingestSecret = process.env["SIFT_INGEST_SECRET"];
  const supabaseUrl = getSupabaseUrl();
  const supabaseKey = getSupabaseAnonKey();
  const orgId = opts.orgId ?? process.env["SIFT_ORG_ID"];

  if ((!supabaseUrl || !supabaseKey) && (!dashboardUrl || !ingestSecret)) {
    process.stderr.write(
      "[Sift Server] No Supabase or dashboard ingestion credentials — instance heartbeat disabled.\n"
    );
    return null;
  }
  if (!orgId) {
    process.stderr.write(
      "[Sift Server] SIFT_ORG_ID not set — instance heartbeat disabled.\n"
    );
    return null;
  }

  const client = supabaseUrl && supabaseKey ? createClient(supabaseUrl, supabaseKey) : null;
  const host = getHostname().split(".")[0] ?? "unknown";
  const instanceId = opts.options.instanceId ?? `${host}:${opts.options.port}:${randomUUID().slice(0, 8)}`;
  const intervalMs = opts.intervalMs ?? 60_000;

  const send = async (): Promise<void> => {
    try {
      const stats = opts.server.stats();
      if (dashboardUrl && ingestSecret) {
        const res = await fetch(`${dashboardUrl.replace(/\/$/, "")}/api/ingest/heartbeat`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${ingestSecret}`,
          },
          body: JSON.stringify({
            kind: "server",
            id: instanceId,
            orgId,
            hostname: host,
            port: opts.options.port,
            upstreamCount: stats.upstreamCount,
            activeSessions: stats.activeSessions,
            toolCallsTotal: stats.toolCallsTotal,
            toolCallsBlocked: stats.toolCallsBlocked,
            status: "online",
            siftVersion: "0.1.0",
            heartbeatAt: new Date().toISOString(),
          }),
        });
        if (!res.ok) {
          process.stderr.write(`[Sift Server] Dashboard heartbeat error: HTTP ${res.status}\n`);
        }
        return;
      }

      const { error } = await client!.from("sift_server_instances").upsert(
        {
          id: instanceId,
          org_id: orgId,
          hostname: host,
          port: opts.options.port,
          upstream_count: stats.upstreamCount,
          active_sessions: stats.activeSessions,
          tool_calls_total: stats.toolCallsTotal,
          tool_calls_blocked: stats.toolCallsBlocked,
          status: "online",
          sift_version: "0.1.0",
          heartbeat_at: new Date().toISOString(),
        },
        { onConflict: "id" }
      );
      if (error) {
        process.stderr.write(`[Sift Server] Heartbeat error: ${error.message}\n`);
      }
    } catch (err) {
      process.stderr.write(`[Sift Server] Heartbeat failed: ${String(err)}\n`);
    }
  };

  void send();
  const timer = setInterval(() => { void send(); }, intervalMs);
  timer.unref();

  process.stderr.write(
    `[Sift Server] Heartbeat enabled (instance=${instanceId}, every ${intervalMs / 1000}s).\n`
  );

  return () => {
    clearInterval(timer);
    // Fire-and-forget offline upsert.
    if (client) {
      void client
        .from("sift_server_instances")
        .update({ status: "offline", heartbeat_at: new Date().toISOString() })
        .eq("id", instanceId);
    }
  };
}
