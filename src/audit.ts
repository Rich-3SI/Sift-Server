import { DatabaseSync } from "node:sqlite";
import { appendFile } from "node:fs/promises";
import { mkdirSync } from "fs";
import { dirname, join } from "path";
import { homedir } from "os";

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
      org_id TEXT,
      session_id TEXT,
      client_name TEXT,
      sequence_number INTEGER,
      created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_logs(timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_action    ON audit_logs(action);
    CREATE INDEX IF NOT EXISTS idx_tool      ON audit_logs(tool);
    CREATE INDEX IF NOT EXISTS idx_user_id   ON audit_logs(user_id);
    CREATE INDEX IF NOT EXISTS idx_org_id    ON audit_logs(org_id);
  `);

  // Migrate existing DBs that predate later columns.
  try { _db.exec(`ALTER TABLE audit_logs ADD COLUMN user_id TEXT`); } catch { /* already exists */ }
  try { _db.exec(`ALTER TABLE audit_logs ADD COLUMN org_id TEXT`); } catch { /* already exists */ }
  try { _db.exec(`ALTER TABLE audit_logs ADD COLUMN session_id TEXT`); } catch { /* already exists */ }
  try { _db.exec(`ALTER TABLE audit_logs ADD COLUMN client_name TEXT`); } catch { /* already exists */ }
  try { _db.exec(`ALTER TABLE audit_logs ADD COLUMN sequence_number INTEGER`); } catch { /* already exists */ }

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
  pruneAuditLogs(retentionDays);

  const timer = setInterval(() => {
    pruneAuditLogs(retentionDays);
  }, 24 * 60 * 60 * 1000);
  timer.unref();
}

export function closeAuditDbForTests(): void {
  try {
    _db?.close();
  } finally {
    _db = null;
  }
}

// ── Composite ──────────────────────────────────────────────────────────────

export function compositeAudit(...handlers: AuditHandler[]): AuditHandler {
  return async (entry: AuditEntry): Promise<void> => {
    await Promise.allSettled(handlers.map((h) => h(entry)));
  };
}
