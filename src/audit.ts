import { createClient } from "@supabase/supabase-js";
import { DatabaseSync } from "node:sqlite";
import { appendFile } from "node:fs/promises";
import { mkdirSync } from "fs";
import { dirname, join } from "path";
import { homedir } from "os";
import { buildSupabaseClientOptions } from "./supabase-auth.js";

export interface AuditEntry {
  id: string;
  timestamp: string;
  tool: string;
  input: unknown;
  output: unknown;
  action: "allow" | "block" | "redact";
  triggeredRules: string[];
  durationMs: number;
  piiDetected: boolean;
  injectionDetected: boolean;
  userId?: string;
  orgId?: string;
  sessionId?: string;
  clientName?: string;
  sequenceNumber?: number;
}

export type AuditHandler = (entry: AuditEntry) => Promise<void>;

export interface WebhookAuditOptions {
  url: string;
  headers?: Record<string, string>;
  bearerToken?: string;
  timeoutMs?: number;
}

type SupabaseAuditRow = {
  id: string;
  timestamp: string;
  tool: string;
  input: unknown;
  output: unknown;
  action: AuditEntry["action"];
  triggered_rules: string[];
  duration_ms: number;
  pii_detected: boolean;
  injection_detected: boolean;
  user_id: string | null;
  org_id: string | null;
  session_id: string | null;
  client_name: string | null;
  sequence_number: number | null;
};

// ── Console ────────────────────────────────────────────────────────────────

export async function consoleAudit(entry: AuditEntry): Promise<void> {
  process.stderr.write(`[Sift] ${JSON.stringify(entry)}\n`);
}

// ── Portable exports (JSONL + webhook) ─────────────────────────────────────

export function jsonlAudit(filePath: string): AuditHandler {
  return async (entry: AuditEntry): Promise<void> => {
    try {
      mkdirSync(dirname(filePath), { recursive: true });
      await appendFile(filePath, `${JSON.stringify(entry)}\n`, "utf8");
    } catch (err) {
      process.stderr.write(`[Sift] JSONL audit export error: ${String(err)}\n`);
    }
  };
}

export function webhookAudit(options: WebhookAuditOptions): AuditHandler {
  return async (entry: AuditEntry): Promise<void> => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), options.timeoutMs ?? 5_000);
    try {
      const headers: Record<string, string> = {
        "Content-Type": "application/json",
        ...(options.headers ?? {}),
      };
      if (options.bearerToken) headers["Authorization"] = `Bearer ${options.bearerToken}`;

      const res = await fetch(options.url, {
        method: "POST",
        headers,
        body: JSON.stringify(entry),
        signal: controller.signal,
      });
      if (!res.ok) {
        process.stderr.write(`[Sift] Webhook audit export error: HTTP ${res.status}\n`);
      }
    } catch (err) {
      process.stderr.write(`[Sift] Webhook audit export error: ${String(err)}\n`);
    } finally {
      clearTimeout(timeout);
    }
  };
}

// ── SQLite (local fallback — always available, no config needed) ───────────

let _db: DatabaseSync | null = null;

function getDb(): DatabaseSync {
  if (_db) return _db;

  const dbDir = process.env["SIFT_DB_PATH"] ?? join(homedir(), ".sift");
  mkdirSync(dbDir, { recursive: true });

  _db = new DatabaseSync(join(dbDir, "audit.db"));
  _db.exec(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      timestamp TEXT NOT NULL,
      tool TEXT NOT NULL,
      input TEXT,
      output TEXT,
      action TEXT CHECK (action IN ('allow','block','redact')),
      triggered_rules TEXT,
      duration_ms INTEGER,
      pii_detected INTEGER DEFAULT 0,
      injection_detected INTEGER DEFAULT 0,
      user_id TEXT,
      supabase_sent_at TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_logs(timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_action    ON audit_logs(action);
    CREATE INDEX IF NOT EXISTS idx_tool      ON audit_logs(tool);
    CREATE INDEX IF NOT EXISTS idx_user_id   ON audit_logs(user_id);
  `);
  // Migrate existing DBs that predate later columns
  try { _db.exec(`ALTER TABLE audit_logs ADD COLUMN user_id TEXT`); } catch { /* already exists */ }
  try { _db.exec(`ALTER TABLE audit_logs ADD COLUMN session_id TEXT`); } catch { /* already exists */ }
  try { _db.exec(`ALTER TABLE audit_logs ADD COLUMN client_name TEXT`); } catch { /* already exists */ }
  try { _db.exec(`ALTER TABLE audit_logs ADD COLUMN sequence_number INTEGER`); } catch { /* already exists */ }
  try { _db.exec(`ALTER TABLE audit_logs ADD COLUMN org_id TEXT`); } catch { /* already exists */ }
  try { _db.exec(`ALTER TABLE audit_logs ADD COLUMN supabase_sent_at TEXT`); } catch { /* already exists */ }
  try { _db.exec(`CREATE INDEX IF NOT EXISTS idx_supabase_pending ON audit_logs(supabase_sent_at, org_id, timestamp)`); } catch { /* best effort */ }

  return _db;
}

export async function sqliteAudit(entry: AuditEntry): Promise<void> {
  try {
    const db = getDb();
    db.prepare(`
      INSERT OR IGNORE INTO audit_logs
        (id, timestamp, tool, input, output, action, triggered_rules,
         duration_ms, pii_detected, injection_detected, user_id, org_id,
         session_id, client_name, sequence_number)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      entry.id,
      entry.timestamp,
      entry.tool,
      JSON.stringify(entry.input),
      JSON.stringify(entry.output),
      entry.action,
      JSON.stringify(entry.triggeredRules),
      entry.durationMs,
      entry.piiDetected ? 1 : 0,
      entry.injectionDetected ? 1 : 0,
      entry.userId ?? null,
      entry.orgId ?? null,
      entry.sessionId ?? null,
      entry.clientName ?? null,
      entry.sequenceNumber ?? null,
    );
  } catch (err) {
    process.stderr.write(`[Sift] SQLite audit error: ${String(err)}\n`);
  }
}

function auditEntryToSupabaseRow(entry: AuditEntry): SupabaseAuditRow {
  return {
    id: entry.id,
    timestamp: entry.timestamp,
    tool: entry.tool,
    input: entry.input,
    output: entry.output,
    action: entry.action,
    triggered_rules: entry.triggeredRules,
    duration_ms: entry.durationMs,
    pii_detected: entry.piiDetected,
    injection_detected: entry.injectionDetected,
    user_id: entry.userId ?? null,
    org_id: entry.orgId ?? null,
    session_id: entry.sessionId ?? null,
    client_name: entry.clientName ?? null,
    sequence_number: entry.sequenceNumber ?? null,
  };
}

function sqliteRowToSupabaseRow(row: Record<string, unknown>): SupabaseAuditRow {
  return {
    id: String(row.id),
    timestamp: String(row.timestamp),
    tool: String(row.tool),
    input: safeParseJson(row.input),
    output: safeParseJson(row.output),
    action: row.action as AuditEntry["action"],
    triggered_rules: safeParseJson(row.triggered_rules, []) as string[],
    duration_ms: Number(row.duration_ms ?? 0),
    pii_detected: Boolean(row.pii_detected),
    injection_detected: Boolean(row.injection_detected),
    user_id: row.user_id ? String(row.user_id) : null,
    org_id: row.org_id ? String(row.org_id) : null,
    session_id: row.session_id ? String(row.session_id) : null,
    client_name: row.client_name ? String(row.client_name) : null,
    sequence_number: row.sequence_number === null || row.sequence_number === undefined
      ? null
      : Number(row.sequence_number),
  };
}

function safeParseJson(value: unknown, fallback: unknown = null): unknown {
  if (typeof value !== "string") return fallback;
  try {
    return JSON.parse(value) as unknown;
  } catch {
    return fallback;
  }
}

function markSupabaseSent(ids: string[]): void {
  if (ids.length === 0) return;
  try {
    const db = getDb();
    const stmt = db.prepare(`UPDATE audit_logs SET supabase_sent_at = ? WHERE id = ?`);
    const sentAt = new Date().toISOString();
    for (const id of ids) stmt.run(sentAt, id);
  } catch (err) {
    process.stderr.write(`[Sift] SQLite audit flush marker error: ${String(err)}\n`);
  }
}

function getPendingSupabaseRows(limit: number): SupabaseAuditRow[] {
  try {
    const db = getDb();
    const rows = db.prepare(`
      SELECT id, timestamp, tool, input, output, action, triggered_rules,
             duration_ms, pii_detected, injection_detected, user_id, org_id,
             session_id, client_name, sequence_number
      FROM audit_logs
      WHERE supabase_sent_at IS NULL
        AND org_id IS NOT NULL
      ORDER BY timestamp ASC
      LIMIT ?
    `).all(limit) as Record<string, unknown>[];

    return rows.map(sqliteRowToSupabaseRow);
  } catch (err) {
    process.stderr.write(`[Sift] SQLite audit flush read error: ${String(err)}\n`);
    return [];
  }
}

// ── Audit log retention ──────────────────────────────────────────────────────

/**
 * Delete audit log entries older than the specified number of days.
 * Runs against the local SQLite database.
 */
export function pruneAuditLogs(retentionDays = 90): number {
  try {
    const db = getDb();
    const cutoff = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000).toISOString();
    const result = db.prepare(`DELETE FROM audit_logs WHERE timestamp < ?`).run(cutoff);
    const deleted = (result as { changes?: number }).changes ?? 0;
    if (deleted > 0) {
      process.stderr.write(`[Sift] Pruned ${deleted} audit log entries older than ${retentionDays} days.\n`);
    }
    return deleted;
  } catch (err) {
    process.stderr.write(`[Sift] Audit prune error: ${String(err)}\n`);
    return 0;
  }
}

/**
 * Start a periodic retention job that prunes old audit logs.
 * Runs once on startup and then every 24 hours.
 */
export function startRetentionJob(retentionDays = 90): void {
  // Run once immediately
  pruneAuditLogs(retentionDays);

  // Then every 24 hours
  const timer = setInterval(() => {
    pruneAuditLogs(retentionDays);
  }, 24 * 60 * 60 * 1000);
  timer.unref();
}

// ── Supabase (uses hardcoded config, falls back to env vars) ────────────────

import { getSupabaseUrl, getSupabaseAnonKey } from "./sift-server.js";

async function insertSupabaseAuditRows(rows: SupabaseAuditRow[]): Promise<{ ok: boolean; error?: string }> {
  const supabaseUrl = getSupabaseUrl();
  const supabaseKey = getSupabaseAnonKey();
  if (!supabaseUrl || !supabaseKey || rows.length === 0) {
    return { ok: false, error: "Supabase credentials unavailable" };
  }

  try {
    const options = buildSupabaseClientOptions();
    if (!options && rows.some((row) => row.org_id)) {
      return { ok: false, error: "Supabase user auth unavailable" };
    }

    const client = options
      ? createClient(supabaseUrl, supabaseKey, options)
      : createClient(supabaseUrl, supabaseKey);
    const { error } = await client.from("audit_logs").upsert(rows, { onConflict: "id" });
    if (error) return { ok: false, error: error.message };
    return { ok: true };
  } catch (err) {
    return { ok: false, error: String(err) };
  }
}

function getDashboardIngestUrl(): string {
  return process.env["SIFT_DASHBOARD_INGEST_URL"]
    ?? process.env["SIFT_DASHBOARD_URL"]
    ?? "";
}

function getDashboardIngestSecret(): string {
  return process.env["SIFT_INGEST_SECRET"] ?? "";
}

async function insertDashboardAuditRows(rows: SupabaseAuditRow[]): Promise<{ ok: boolean; error?: string }> {
  const dashboardUrl = getDashboardIngestUrl();
  const ingestSecret = getDashboardIngestSecret();
  if (!dashboardUrl || !ingestSecret || rows.length === 0) {
    return { ok: false, error: "Dashboard ingestion unavailable" };
  }

  try {
    const res = await fetch(`${dashboardUrl.replace(/\/$/, "")}/api/ingest/audits`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${ingestSecret}`,
      },
      body: JSON.stringify({ logs: rows }),
    });
    if (!res.ok) return { ok: false, error: `HTTP ${res.status}` };
    return { ok: true };
  } catch (err) {
    return { ok: false, error: String(err) };
  }
}

async function insertRemoteAuditRows(rows: SupabaseAuditRow[]): Promise<{ ok: boolean; error?: string }> {
  if (getDashboardIngestUrl() && getDashboardIngestSecret()) {
    return insertDashboardAuditRows(rows);
  }
  return insertSupabaseAuditRows(rows);
}

export async function flushPendingSupabaseAudits(limit = 100): Promise<number> {
  const rows = getPendingSupabaseRows(limit);
  if (rows.length === 0) return 0;

  const result = await insertRemoteAuditRows(rows);
  if (!result.ok) {
    process.stderr.write(`[Sift] Remote audit flush error: ${result.error ?? "unknown error"}\n`);
    return 0;
  }

  markSupabaseSent(rows.map((row) => row.id));
  process.stderr.write(`[Sift] Flushed ${rows.length} pending audit log${rows.length === 1 ? "" : "s"} to remote backend.\n`);
  return rows.length;
}

export function startSupabaseAuditFlushJob(intervalMs = 60_000, batchSize = 100): void {
  const run = (): void => {
    void flushPendingSupabaseAudits(batchSize);
  };

  run();
  const timer = setInterval(run, intervalMs);
  timer.unref();
}

export function getPendingSupabaseAuditCountForTests(): number {
  try {
    const db = getDb();
    const row = db.prepare(`
      SELECT COUNT(*) AS count
      FROM audit_logs
      WHERE supabase_sent_at IS NULL
        AND org_id IS NOT NULL
    `).get() as { count?: number } | undefined;
    return Number(row?.count ?? 0);
  } catch {
    return 0;
  }
}

export function closeAuditDbForTests(): void {
  try {
    _db?.close();
  } finally {
    _db = null;
  }
}

export function supabaseAudit(entry: AuditEntry): Promise<void> {
  return new Promise((resolve) => {
    const hasDashboardIngest = Boolean(getDashboardIngestUrl() && getDashboardIngestSecret());
    const hasSupabase = Boolean(getSupabaseUrl() && getSupabaseAnonKey());

    // Only send audit logs for enterprise installations (must have org_id)
    if (!entry.orgId || (!hasDashboardIngest && !hasSupabase)) {
      resolve();
      return;
    }

    Promise.resolve(insertRemoteAuditRows([auditEntryToSupabaseRow(entry)]))
      .then((result) => {
        if (result.ok) {
          markSupabaseSent([entry.id]);
        } else {
          process.stderr.write(`[Sift] Remote audit error: ${result.error ?? "unknown error"}\n`);
        }
        resolve();
      })
      .catch((err: unknown) => {
        process.stderr.write(`[Sift] Supabase audit exception: ${String(err)}\n`);
        resolve();
      });
  });
}

// ── Notification (sends alerts to dashboard for email/Slack delivery) ──────

export function notificationAudit(
  dashboardUrl: string,
  secret: string
): AuditHandler {
  return async (entry: AuditEntry): Promise<void> => {
    // Only notify on blocks and redacts
    if (entry.action === "allow") return;

    try {
      const url = `${dashboardUrl.replace(/\/$/, "")}/api/notifications/send`;
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);

      await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${secret}`,
        },
        body: JSON.stringify({
          id: entry.id,
          timestamp: entry.timestamp,
          tool: entry.tool,
          action: entry.action,
          triggeredRules: entry.triggeredRules,
          piiDetected: entry.piiDetected,
          injectionDetected: entry.injectionDetected,
          userId: entry.userId,
        }),
        signal: controller.signal,
      });

      clearTimeout(timeout);
    } catch {
      // Fire-and-forget: don't let notification failures block the proxy
    }
  };
}

// ── Composite ──────────────────────────────────────────────────────────────

export function compositeAudit(...handlers: AuditHandler[]): AuditHandler {
  return async (entry: AuditEntry): Promise<void> => {
    await Promise.allSettled(handlers.map((h) => h(entry)));
  };
}
