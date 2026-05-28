#!/usr/bin/env node
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const config = {
  url: process.env.SIFT_QUICKSTART_MCP_URL ?? "http://127.0.0.1:18080/mcp",
  adminUrl: process.env.SIFT_QUICKSTART_ADMIN_URL ?? "http://127.0.0.1:18081",
  key: process.env.SIFT_QUICKSTART_API_KEY ?? "sk-sift-quickstart-dev",
  adminSecret: process.env.SIFT_QUICKSTART_ADMIN_SECRET ?? "change-me-quickstart-admin",
};

const results = [];
let client;

try {
  await waitForReady(config.adminUrl);

  const health = await fetchJson(`${config.adminUrl}/healthz`);
  pass(health.status === 200 && health.body.status === "alive", "/healthz reports alive");

  const ready = await fetchJson(`${config.adminUrl}/readyz`);
  pass(ready.status === 200 && ready.body.status === "ready", "/readyz reports ready");

  const missingAuth = await fetch(config.url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize" }),
  });
  pass(missingAuth.status === 401, "/mcp rejects missing bearer token");

  const invalidAuth = await fetch(config.url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: "Bearer invalid",
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize" }),
  });
  pass(invalidAuth.status === 401, "/mcp rejects invalid bearer token");

  client = new Client(
    { name: "sift-quickstart-smoke-test", version: "0.1.0" },
    { capabilities: {} }
  );
  const transport = new StreamableHTTPClientTransport(
    new URL(config.url),
    { requestInit: { headers: { Authorization: `Bearer ${config.key}` } } }
  );
  await client.connect(transport);
  pass(true, "MCP client connects with quickstart API key");

  const tools = await client.listTools();
  const toolNames = tools.tools.map((tool) => tool.name).sort();
  pass(
    ["delete_repo", "echo", "status"].every((name) => toolNames.includes(name)),
    `Sift Server exposes expected tools: ${toolNames.join(", ")}`
  );

  const allowedSimulation = await fetchJson(`${config.adminUrl}/admin/simulate`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-sift-admin-secret": config.adminSecret,
    },
    body: JSON.stringify({
      tool: "status",
      input: {},
      userId: "quickstart-user",
      orgId: "quickstart-org",
    }),
  });
  pass(
    allowedSimulation.status === 200 && allowedSimulation.body.verdict?.action === "allow",
    "Admin simulation dry-runs an allowed tool call"
  );

  const blockedSimulation = await fetchJson(`${config.adminUrl}/admin/simulate`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-sift-admin-secret": config.adminSecret,
    },
    body: JSON.stringify({
      tool: "delete_repo",
      input: { repo: "production" },
      userId: "quickstart-user",
      orgId: "quickstart-org",
    }),
  });
  pass(
    blockedSimulation.status === 200
      && blockedSimulation.body.verdict?.action === "block"
      && blockedSimulation.body.verdict?.triggeredRules?.includes("quickstart/block-delete-repo"),
    "Admin simulation dry-runs a blocked tool call"
  );

  const status = await client.callTool({ name: "status", arguments: {} });
  pass(readFirstText(status) === "quickstart:ok", "Allowed status tool reaches upstream");

  const echo = await client.callTool({ name: "echo", arguments: { text: "hello" } });
  pass(readFirstText(echo) === "quickstart:echo:hello", "Allowed echo tool reaches upstream");

  const blocked = await client.callTool({ name: "delete_repo", arguments: { repo: "production" } });
  pass(blocked.isError === true, "Blocked delete_repo returns MCP error result");
  pass(readFirstText(blocked).toLowerCase().includes("blocked"), "Blocked result includes Sift message");

  const stats = await fetchJson(`${config.adminUrl}/stats`, {
    headers: { "x-sift-admin-secret": config.adminSecret },
  });
  pass(
    stats.status === 200
      && Number(stats.body.toolCallsTotal ?? 0) >= 3
      && Number(stats.body.toolCallsBlocked ?? 0) >= 1,
    "Stats counted allowed and blocked calls"
  );

  printSummary();
} catch (err) {
  fail(String(err));
  printSummary();
  process.exitCode = 1;
} finally {
  await client?.close().catch(() => {});
}

async function waitForReady(adminUrl) {
  const deadline = Date.now() + 60_000;
  let lastError = "";
  while (Date.now() < deadline) {
    try {
      const ready = await fetchJson(`${adminUrl}/readyz`);
      if (ready.status === 200 && ready.body.status === "ready") return;
      lastError = `HTTP ${ready.status}: ${JSON.stringify(ready.body)}`;
    } catch (err) {
      lastError = String(err);
    }
    await sleep(1_000);
  }
  throw new Error(`Quickstart did not become ready within 60s. Last error: ${lastError}`);
}

async function fetchJson(url, init = {}) {
  const res = await fetch(url, init);
  const text = await res.text();
  let body = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = text;
  }
  return { status: res.status, body };
}

function pass(condition, message) {
  if (!condition) throw new Error(message);
  results.push({ ok: true, message });
}

function fail(message) {
  results.push({ ok: false, message });
}

function printSummary() {
  for (const result of results) {
    process.stdout.write(`${result.ok ? "[PASS]" : "[FAIL]"} ${result.message}\n`);
  }
}

function readFirstText(result) {
  const content = result?.content;
  if (!Array.isArray(content)) return "";
  return String(content[0]?.text ?? "");
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
