import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { UpstreamPool } from "../src/upstream-pool.js";

test("stdio upstream env does not inherit parent process secrets when overrides are configured", async () => {
  const dir = mkdtempSync(join(process.cwd(), ".tmp-upstream-env-"));
  const capturePath = join(dir, "env.json");
  const serverPath = join(dir, "server.mjs");

  writeFileSync(serverPath, `
import { writeFileSync } from "node:fs";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

writeFileSync(process.env.SIFT_ENV_CAPTURE, JSON.stringify({
  adminSecret: process.env.SIFT_ADMIN_SECRET ?? null,
  explicit: process.env.EXPLICIT_UPSTREAM_ENV ?? null,
  pathPresent: typeof process.env.PATH === "string" && process.env.PATH.length > 0
}));

const server = new Server(
  { name: "env-capture", version: "0.1.0" },
  { capabilities: { tools: {} } }
);
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{ name: "env_status", description: "Report status", inputSchema: { type: "object" } }]
}));
await server.connect(new StdioServerTransport());
`, "utf8");

  const previousSecret = process.env["SIFT_ADMIN_SECRET"];
  process.env["SIFT_ADMIN_SECRET"] = "parent-admin-secret";
  const pool = new UpstreamPool();

  try {
    await pool.connectAll([{
      name: "env-capture",
      command: [process.execPath, serverPath],
      env: {
        SIFT_ENV_CAPTURE: capturePath,
        EXPLICIT_UPSTREAM_ENV: "explicit-ok",
      },
    }]);

    const captured = JSON.parse(readFileSync(capturePath, "utf8")) as {
      adminSecret: string | null;
      explicit: string | null;
      pathPresent: boolean;
    };
    assert.equal(captured.adminSecret, null);
    assert.equal(captured.explicit, "explicit-ok");
    assert.equal(captured.pathPresent, true);
  } finally {
    await pool.closeAll();
    if (previousSecret === undefined) {
      delete process.env["SIFT_ADMIN_SECRET"];
    } else {
      process.env["SIFT_ADMIN_SECRET"] = previousSecret;
    }
    rmSync(dir, { recursive: true, force: true });
  }
});
