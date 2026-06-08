import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type ServerResponse, type Server as HttpServer } from "node:http";
import { Server as McpServer } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import {
  CallToolRequestSchema,
  GetPromptRequestSchema,
  ListPromptsRequestSchema,
  ListResourceTemplatesRequestSchema,
  ListResourcesRequestSchema,
  ListToolsRequestSchema,
  ReadResourceRequestSchema,
  type CallToolResult,
} from "@modelcontextprotocol/sdk/types.js";
import { ConfigStore } from "../../src/config-store.js";
import { UpstreamPool } from "../../src/upstream-pool.js";
import { SiftServer } from "../src/server.js";
import { resolveServerOptions } from "../src/config.js";
import { startHealthServer } from "../src/health.js";
import type { AuditEntry } from "../../src/audit.js";

const UPSTREAM_PORT = 18120;
const SIFT_PORT = 18121;
const FASTMCP_TOKEN = "fastmcp-secret";

function startMockFastMcp(): Promise<HttpServer> {
  const http = createServer((req, res) => {
    void handleMockRequest(req, res);
  });
  return new Promise((resolve, reject) => {
    http.listen(UPSTREAM_PORT, "127.0.0.1", () => resolve(http));
    http.on("error", reject);
  });
}

async function handleMockRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (req.headers["x-fastmcp-token"] !== FASTMCP_TOKEN) {
    res.writeHead(401, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "missing upstream auth" }));
    return;
  }

  const mcp = new McpServer(
    { name: "mock-fastmcp", version: "0.1.0" },
    { capabilities: { tools: {}, resources: {}, prompts: {} } }
  );
  mcp.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      { name: "echo", description: "Echo text", inputSchema: { type: "object" } },
      { name: "delete_repo", description: "Dangerous test tool", inputSchema: { type: "object" } },
    ],
  }));
  mcp.setRequestHandler(CallToolRequestSchema, async (request): Promise<CallToolResult> => ({
    content: [{ type: "text", text: `fastmcp:${request.params.name}` }],
  }));
  mcp.setRequestHandler(ListResourcesRequestSchema, async () => ({
    resources: [{ uri: "fastmcp://status", name: "FastMCP status" }],
  }));
  mcp.setRequestHandler(ListResourceTemplatesRequestSchema, async () => ({
    resourceTemplates: [{
      uriTemplate: "fastmcp://status/{name}",
      name: "FastMCP status template",
    }],
  }));
  mcp.setRequestHandler(ReadResourceRequestSchema, async (request) => ({
    contents: [{ uri: request.params.uri, text: "fastmcp:resource" }],
  }));
  mcp.setRequestHandler(ListPromptsRequestSchema, async () => ({
    prompts: [{ name: "fastmcp-review", description: "Review FastMCP output" }],
  }));
  mcp.setRequestHandler(GetPromptRequestSchema, async () => ({
    messages: [{
      role: "user",
      content: { type: "text", text: "fastmcp:prompt" },
    }],
  }));

  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  await mcp.connect(transport);
  await transport.handleRequest(req, res);
}

describe("Sift Server FastMCP integration", () => {
  let upstream: HttpServer;
  let server: SiftServer;
  let pool: UpstreamPool;
  let client: Client;
  let transport: StreamableHTTPClientTransport;
  let health: HttpServer;
  const audits: AuditEntry[] = [];

  before(async () => {
    upstream = await startMockFastMcp();

    const configStore = new ConfigStore({
      upstreams: [{
        name: "company-fastmcp",
        url: `http://127.0.0.1:${UPSTREAM_PORT}/mcp`,
        headers: { "x-fastmcp-token": FASTMCP_TOKEN },
      } as never],
      defaultPolicy: {
        policies: [],
        rules: [{
          id: "block-dangerous",
          description: "Block dangerous FastMCP tool",
          match: "() => false",
          condition: { tools: ["delete_repo"] },
          action: "block",
        }, {
          id: "block-secret-resource",
          description: "Block secret MCP resources",
          match: "() => false",
          condition: { tools: ["mcp.read_resource"], inputContains: { uri: "secret" } },
          action: "block",
        }, {
          id: "block-secret-prompt",
          description: "Block secret MCP prompts",
          match: "() => false",
          condition: { tools: ["mcp.get_prompt"], inputContains: { name: "secret" } },
          action: "block",
        }],
      },
    });

    pool = new UpstreamPool();
    await pool.connectAll(configStore.get().upstreams ?? []);

    server = new SiftServer({
      configStore,
      pool,
      auditHandler: async (entry) => { audits.push(entry); },
      options: resolveServerOptions({
        upstreams: configStore.get().upstreams,
        server: { port: SIFT_PORT, host: "127.0.0.1", adminPort: 18122 },
        auth: {
          mode: "api-key",
          apiKeys: [
            { key: "sk-fastmcp", userId: "pilot-user", orgId: "pilot-org", email: "pilot@example.com" },
            { key: "sk-fastmcp-other", userId: "other-user", orgId: "pilot-org", email: "other@example.com" },
          ],
        },
      }),
    });
    await server.start();

    health = startHealthServer(18123, "127.0.0.1", pool, server, configStore);

    client = new Client({ name: "fastmcp-test-client", version: "0.1.0" }, { capabilities: {} });
    transport = new StreamableHTTPClientTransport(
      new URL(`http://127.0.0.1:${SIFT_PORT}/mcp`),
      { requestInit: { headers: { Authorization: "Bearer sk-fastmcp" } } }
    );
    await client.connect(transport);
  });

  after(async () => {
    await client?.close().catch(() => {});
    await new Promise<void>((resolve) => health?.close(() => resolve()));
    await server?.stop();
    await pool?.closeAll();
    await new Promise<void>((resolve) => upstream.close(() => resolve()));
  });

  it("forwards authenticated FastMCP tools, resources, prompts, and audit events", async () => {
    const tools = await client.listTools();
    assert.deepEqual(tools.tools.map((tool) => tool.name).sort(), ["delete_repo", "echo"]);

    const resources = await client.listResources();
    assert.equal(resources.resources[0]?.uri, "fastmcp://status");

    const resourceTemplates = await client.listResourceTemplates();
    assert.equal(resourceTemplates.resourceTemplates[0]?.uriTemplate, "fastmcp://status/{name}");

    const resource = await client.readResource({ uri: "fastmcp://status" });
    assert.equal(resource.contents[0]?.uri, "fastmcp://status");
    assert.equal((resource.contents[0] as { text?: string }).text, "fastmcp:resource");

    const prompts = await client.listPrompts();
    assert.equal(prompts.prompts[0]?.name, "fastmcp-review");

    const prompt = await client.getPrompt({ name: "fastmcp-review" });
    assert.equal(prompt.messages[0]?.content.type, "text");
    assert.equal((prompt.messages[0]?.content as { text?: string }).text, "fastmcp:prompt");

    const allowed = await client.callTool({ name: "echo", arguments: { text: "hello" } });
    assert.equal((allowed.content as Array<{ text?: string }>)[0]?.text, "fastmcp:echo");

    const blocked = await client.callTool({ name: "delete_repo", arguments: { repo: "prod" } });
    assert.equal(blocked.isError, true);

    const unknown = await client.callTool({ name: "missing_tool", arguments: { value: "nope" } });
    assert.equal(unknown.isError, true);

    assert.equal(audits.length, 5);
    assert.equal(audits[0]?.tool, "mcp.read_resource");
    assert.equal(audits[0]?.action, "allow");
    assert.equal(audits[1]?.tool, "mcp.get_prompt");
    assert.equal(audits[1]?.action, "allow");
    assert.equal(audits[2]?.action, "allow");
    assert.equal(audits[2]?.orgId, "pilot-org");
    assert.equal(audits[3]?.action, "block");
    assert.deepEqual(audits[3]?.triggeredRules, ["block-dangerous"]);
    assert.equal(audits[4]?.action, "block");
    assert.deepEqual(audits[4]?.triggeredRules, ["unknown-tool"]);
  });

  it("enforces policy on MCP resources and prompts", async () => {
    await assert.rejects(
      client.readResource({ uri: "fastmcp://secret" }),
      /block-secret-resource/
    );

    await assert.rejects(
      client.getPrompt({ name: "secret-review" }),
      /block-secret-prompt/
    );

    const resourceAudit = audits.find((entry) => entry.tool === "mcp.read_resource" && entry.action === "block");
    assert.deepEqual(resourceAudit?.triggeredRules, ["block-secret-resource"]);
    const promptAudit = audits.find((entry) => entry.tool === "mcp.get_prompt" && entry.action === "block");
    assert.deepEqual(promptAudit?.triggeredRules, ["block-secret-prompt"]);
  });

  it("requires matching bearer auth on existing sessions", async () => {
    const sessionId = transport.sessionId;
    assert.ok(sessionId);

    const withoutAuth = await fetch(`http://127.0.0.1:${SIFT_PORT}/mcp`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "mcp-session-id": sessionId,
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 99, method: "tools/list" }),
    });
    assert.equal(withoutAuth.status, 401);

    const mismatchedAuth = await fetch(`http://127.0.0.1:${SIFT_PORT}/mcp`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "mcp-session-id": sessionId,
        Authorization: "Bearer sk-fastmcp-other",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 100, method: "tools/list" }),
    });
    assert.equal(mismatchedAuth.status, 403);
  });

  it("disconnects sessions through the admin endpoint", async () => {
    const sessionId = transport.sessionId;
    assert.ok(sessionId);

    const previous = process.env["SIFT_ADMIN_SECRET"];
    process.env["SIFT_ADMIN_SECRET"] = "admin-fastmcp-secret";
    try {
      const res = await fetch(`http://127.0.0.1:18123/admin/disconnect/${sessionId}`, {
        method: "POST",
        headers: { "x-sift-admin-secret": "admin-fastmcp-secret" },
      });
      assert.equal(res.status, 200);
      assert.equal(server.listSessions().some((session) => session.sessionId === sessionId), false);
    } finally {
      if (previous === undefined) {
        delete process.env["SIFT_ADMIN_SECRET"];
      } else {
        process.env["SIFT_ADMIN_SECRET"] = previous;
      }
    }
  });
});
