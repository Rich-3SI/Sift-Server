import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";
import {
  closeAuditDbForTests,
  getPendingSupabaseAuditCountForTests,
  sqliteAudit,
  type AuditEntry,
} from "../src/audit.js";

const tempDirs: string[] = [];

function makeEntry(overrides: Partial<AuditEntry> = {}): AuditEntry {
  return {
    id: randomUUID(),
    timestamp: new Date().toISOString(),
    tool: "test_tool",
    input: { ok: true },
    output: { result: "ok" },
    action: "allow",
    triggeredRules: [],
    durationMs: 1,
    piiDetected: false,
    injectionDetected: false,
    ...overrides,
  };
}

function useTempAuditDb(): void {
  const dir = mkdtempSync(join(tmpdir(), "sift-audit-"));
  tempDirs.push(dir);
  process.env["SIFT_DB_PATH"] = dir;
  closeAuditDbForTests();
}

afterEach(() => {
  closeAuditDbForTests();
  delete process.env["SIFT_DB_PATH"];
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("SQLite audit rows with org_id are pending until Supabase flush marks them sent", async () => {
  useTempAuditDb();

  await sqliteAudit(makeEntry({ orgId: "org-1" }));

  assert.equal(getPendingSupabaseAuditCountForTests(), 1);
});

test("SQLite audit rows without org_id are not eligible for Supabase flush", async () => {
  useTempAuditDb();

  await sqliteAudit(makeEntry());

  assert.equal(getPendingSupabaseAuditCountForTests(), 0);
});
