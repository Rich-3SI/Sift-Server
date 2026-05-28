import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { jsonlAudit, webhookAudit, type AuditEntry } from "../src/audit.js";

test("jsonlAudit appends one JSON audit entry per line", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sift-jsonl-audit-"));
  const path = join(dir, "exports", "audit.jsonl");

  await jsonlAudit(path)(makeEntry({ tool: "echo" }));
  await jsonlAudit(path)(makeEntry({ tool: "status" }));

  const lines = readFileSync(path, "utf8").trim().split("\n");
  assert.equal(lines.length, 2);
  assert.equal(JSON.parse(lines[0]!).tool, "echo");
  assert.equal(JSON.parse(lines[1]!).tool, "status");
});

test("webhookAudit posts audit entries to an HTTP collector", async () => {
  const received: Array<{ auth?: string; body: unknown }> = [];
  const server = createServer((req, res) => {
    let raw = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => { raw += chunk; });
    req.on("end", () => {
      received.push({
        auth: req.headers.authorization,
        body: JSON.parse(raw),
      });
      res.writeHead(202);
      res.end("ok");
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.listen(0, "127.0.0.1", () => resolve());
    server.on("error", reject);
  });

  try {
    const address = server.address();
    assert.ok(address && typeof address === "object");
    await webhookAudit({
      url: `http://127.0.0.1:${address.port}/ingest`,
      bearerToken: "collector-secret",
    })(makeEntry({ tool: "echo" }));

    assert.equal(received.length, 1);
    assert.equal(received[0]?.auth, "Bearer collector-secret");
    assert.equal((received[0]?.body as AuditEntry).tool, "echo");
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

function makeEntry(overrides: Partial<AuditEntry> = {}): AuditEntry {
  return {
    id: randomUUID(),
    timestamp: new Date().toISOString(),
    tool: "echo",
    input: {},
    output: null,
    action: "allow",
    triggeredRules: [],
    durationMs: 1,
    piiDetected: false,
    injectionDetected: false,
    ...overrides,
  };
}
