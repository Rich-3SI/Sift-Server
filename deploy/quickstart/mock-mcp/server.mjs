import { createServer } from "node:http";
import { Server as McpServer } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

const port = Number.parseInt(process.env.PORT ?? "3000", 10);
const token = process.env.QUICKSTART_MCP_TOKEN ?? "quickstart-local-token";

const http = createServer((req, res) => {
  void handleRequest(req, res).catch((err) => {
    if (!res.headersSent) {
      res.writeHead(500, { "Content-Type": "application/json" });
    }
    res.end(JSON.stringify({ error: String(err) }));
  });
});

http.listen(port, "0.0.0.0", () => {
  process.stderr.write(`[sift-quickstart-mock-mcp] Listening on http://0.0.0.0:${port}/mcp\n`);
});

async function handleRequest(req, res) {
  if (req.url === "/healthz") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: "alive" }));
    return;
  }

  if (req.url !== "/mcp" && req.url !== "/mcp/") {
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Not found. Use POST /mcp" }));
    return;
  }

  const header = req.headers["x-quickstart-token"];
  const presented = Array.isArray(header) ? header[0] : header;
  if (presented !== token) {
    res.writeHead(401, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "missing upstream auth" }));
    return;
  }

  const mcp = new McpServer(
    { name: "sift-quickstart-mock-mcp", version: "0.1.0" },
    { capabilities: { tools: {} } }
  );

  mcp.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: "status",
        description: "Return upstream status.",
        inputSchema: { type: "object", additionalProperties: false },
      },
      {
        name: "echo",
        description: "Echo text through the upstream.",
        inputSchema: {
          type: "object",
          properties: { text: { type: "string" } },
          required: ["text"],
          additionalProperties: false,
        },
      },
      {
        name: "delete_repo",
        description: "Dangerous demo tool that Sift should block.",
        inputSchema: {
          type: "object",
          properties: { repo: { type: "string" } },
          required: ["repo"],
          additionalProperties: false,
        },
      },
    ],
  }));

  mcp.setRequestHandler(CallToolRequestSchema, async (request) => {
    const args = request.params.arguments ?? {};
    if (request.params.name === "status") {
      return { content: [{ type: "text", text: "quickstart:ok" }] };
    }
    if (request.params.name === "echo") {
      return { content: [{ type: "text", text: `quickstart:echo:${String(args.text ?? "")}` }] };
    }
    if (request.params.name === "delete_repo") {
      return { content: [{ type: "text", text: `quickstart:delete:${String(args.repo ?? "")}` }] };
    }
    return {
      content: [{ type: "text", text: `unknown tool: ${request.params.name}` }],
      isError: true,
    };
  });

  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  await mcp.connect(transport);
  await transport.handleRequest(req, res);
}
