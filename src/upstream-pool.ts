import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import {
  type GetPromptResult,
  type Prompt,
  type ReadResourceResult,
  type Resource,
  type ResourceTemplate,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { type UpstreamServer } from "./config-store.js";

// ── Types ─────────────────────────────────────────────────────────────────────

/**
 * Resolved routing entry for a single tool call.
 * `originalName` is the name to use when calling the upstream (may differ from
 * the exposed name when collision-prefixing was applied).
 */
export interface ToolRoute {
  client: Client;
  originalName: string;
  serverName: string;
}

// ── UpstreamPool ──────────────────────────────────────────────────────────────

/**
 * Manages connections to one or more upstream MCP servers and presents their
 * combined tool surface as a single aggregated list.
 *
 * Collision resolution:
 *   - If only one server exposes "read_file", it is listed as "read_file".
 *   - If two servers both expose "read_file", they are listed as
 *     "serverA__read_file" and "serverB__read_file".
 *
 * The routing table maps exposed names back to the correct upstream client and
 * the original (unprefixed) tool name to use when calling it.
 */
export class UpstreamPool {
  private routingTable = new Map<string, ToolRoute>();
  private _aggregatedTools: Tool[] = [];
  private _ready = false;
  private _readyCallbacks: Array<() => void> = [];

  // ── Public API ──────────────────────────────────────────────────────────────

  get allReady(): boolean {
    return this._ready;
  }

  getAggregatedTools(): Tool[] {
    return this._aggregatedTools;
  }

  /** All connected upstream clients, used for fan-out of resources/prompts. */
  getClients(): Array<{ serverName: string; client: Client }> {
    const seen = new Set<Client>();
    const out: Array<{ serverName: string; client: Client }> = [];
    for (const route of this.routingTable.values()) {
      if (seen.has(route.client)) continue;
      seen.add(route.client);
      out.push({ serverName: route.serverName, client: route.client });
    }
    return out;
  }

  async listResources(): Promise<Resource[]> {
    const resources: Resource[] = [];
    for (const { serverName, client } of this.getClients()) {
      try {
        const result = await client.listResources();
        resources.push(...result.resources.map((resource) => ({
          ...resource,
          _meta: { ...(resource._meta ?? {}), siftUpstream: serverName },
        })));
      } catch (err) {
        process.stderr.write(`[Sift] Resource list failed for "${serverName}": ${String(err)}\n`);
      }
    }
    return resources;
  }

  async listPrompts(): Promise<Prompt[]> {
    const prompts: Prompt[] = [];
    for (const { serverName, client } of this.getClients()) {
      try {
        const result = await client.listPrompts();
        prompts.push(...result.prompts.map((prompt) => ({
          ...prompt,
          _meta: { ...(prompt._meta ?? {}), siftUpstream: serverName },
        })));
      } catch (err) {
        process.stderr.write(`[Sift] Prompt list failed for "${serverName}": ${String(err)}\n`);
      }
    }
    return prompts;
  }

  async listResourceTemplates(): Promise<ResourceTemplate[]> {
    const resourceTemplates: ResourceTemplate[] = [];
    for (const { serverName, client } of this.getClients()) {
      try {
        const result = await client.listResourceTemplates();
        resourceTemplates.push(...result.resourceTemplates.map((template) => ({
          ...template,
          _meta: { ...(template._meta ?? {}), siftUpstream: serverName },
        })));
      } catch (err) {
        process.stderr.write(`[Sift] Resource template list failed for "${serverName}": ${String(err)}\n`);
      }
    }
    return resourceTemplates;
  }

  async readResource(uri: string): Promise<ReadResourceResult> {
    const errors: string[] = [];
    for (const { serverName, client } of this.getClients()) {
      try {
        const result = await client.readResource({ uri });
        return {
          ...result,
          contents: result.contents.map((content) => ({
            ...content,
            _meta: { ...(content._meta ?? {}), siftUpstream: serverName },
          })),
        };
      } catch (err) {
        errors.push(`${serverName}: ${String(err)}`);
      }
    }
    throw new Error(`Resource not found or unreadable: ${uri}. ${errors.join("; ")}`);
  }

  async getPrompt(name: string, args?: Record<string, string>): Promise<GetPromptResult> {
    const errors: string[] = [];
    for (const { serverName, client } of this.getClients()) {
      try {
        const result = await client.getPrompt({ name, arguments: args });
        return {
          ...result,
          _meta: { ...(result._meta ?? {}), siftUpstream: serverName },
        };
      } catch (err) {
        errors.push(`${serverName}: ${String(err)}`);
      }
    }
    throw new Error(`Prompt not found or unavailable: ${name}. ${errors.join("; ")}`);
  }

  route(exposedName: string): ToolRoute | undefined {
    return this.routingTable.get(exposedName);
  }

  async closeAll(): Promise<void> {
    const clients = this.getClients().map(({ client }) => client);
    await Promise.allSettled(clients.map((client) => client.close()));
    this.routingTable.clear();
    this._aggregatedTools = [];
    this._ready = false;
  }

  /**
   * Connect to all servers concurrently. Uses Promise.allSettled so a single
   * failing upstream does not prevent the others from being used.
   * Throws only if ZERO upstreams connected successfully.
   */
  async connectAll(servers: UpstreamServer[]): Promise<void> {
    if (servers.length === 0) {
      throw new Error("No upstream servers configured");
    }

    const results = await Promise.allSettled(
      servers.map((s) => this.connectOne(s))
    );

    const connected: Array<{ serverName: string; client: Client; tools: Tool[] }> = [];
    for (let i = 0; i < results.length; i++) {
      const result = results[i]!;
      if (result.status === "fulfilled") {
        connected.push(result.value);
      } else {
        process.stderr.write(
          `[Sift] ✗ Failed to connect to upstream "${servers[i]!.name}": ${String(result.reason)}\n`
        );
      }
    }

    if (connected.length === 0) {
      throw new Error("No upstream servers connected successfully — cannot start.");
    }

    this.buildRoutingTable(connected);
    this._ready = true;
    for (const cb of this._readyCallbacks) cb();
    this._readyCallbacks = [];
  }

  /**
   * Waits until all upstreams have connected and their tool lists are known.
   * Rejects if the deadline is exceeded.
   */
  waitForAll(timeoutMs = 30000): Promise<void> {
    if (this._ready) return Promise.resolve();
    return new Promise((resolve, reject) => {
      const deadline = setTimeout(() => {
        reject(new Error(`Upstream servers did not become ready within ${timeoutMs}ms`));
      }, timeoutMs);
      this._readyCallbacks.push(() => {
        clearTimeout(deadline);
        resolve();
      });
    });
  }

  // ── Private helpers ─────────────────────────────────────────────────────────

  private async connectOne(
    server: UpstreamServer
  ): Promise<{ serverName: string; client: Client; tools: Tool[] }> {
    if (server.url) {
      return this.connectHttp(server);
    }
    return this.connectStdio(server);
  }

  private async connectStdio(
    server: UpstreamServer
  ): Promise<{ serverName: string; client: Client; tools: Tool[] }> {
    const cmd = server.command ?? [];
    if (cmd.length === 0) {
      throw new Error(`Upstream "${server.name}" has neither a command nor a url`);
    }

    const [exe, ...args] = cmd;
    const client = new Client(
      { name: `sift-upstream-${server.name}`, version: "0.1.0" },
      { capabilities: {} }
    );

    const envOverride = server.env ? { ...server.env } : undefined;

    const transport = new StdioClientTransport({ command: exe!, args, env: envOverride });
    await client.connect(transport);
    process.stderr.write(`[Sift] ✓ Connected to "${server.name}" via stdio\n`);

    const { tools } = await client.listTools();
    return { serverName: server.name, client, tools };
  }

  private async connectHttp(
    server: UpstreamServer
  ): Promise<{ serverName: string; client: Client; tools: Tool[] }> {
    const url = new URL(server.url!);
    const requestInit = server.headers ? { headers: server.headers } : undefined;

    // Try StreamableHTTP first, fall back to legacy SSE
    try {
      const client = new Client(
        { name: `sift-upstream-${server.name}`, version: "0.1.0" },
        { capabilities: {} }
      );
      const transport = new StreamableHTTPClientTransport(url, { requestInit });
      await client.connect(transport);
      process.stderr.write(`[Sift] ✓ Connected to "${server.name}" via StreamableHTTP: ${url.href}\n`);
      const { tools } = await client.listTools();
      return { serverName: server.name, client, tools };
    } catch {
      process.stderr.write(`[Sift] StreamableHTTP failed for "${server.name}", trying SSE...\n`);
    }

    const client = new Client(
      { name: `sift-upstream-${server.name}`, version: "0.1.0" },
      { capabilities: {} }
    );
    const sseTransport = new SSEClientTransport(url, { requestInit });
    await client.connect(sseTransport);
    process.stderr.write(`[Sift] ✓ Connected to "${server.name}" via SSE: ${url.href}\n`);
    const { tools } = await client.listTools();
    return { serverName: server.name, client, tools };
  }

  private buildRoutingTable(
    connected: Array<{ serverName: string; client: Client; tools: Tool[] }>
  ): void {
    // Count how many servers expose each bare tool name
    const nameCounts = new Map<string, number>();
    for (const { tools } of connected) {
      for (const tool of tools) {
        nameCounts.set(tool.name, (nameCounts.get(tool.name) ?? 0) + 1);
      }
    }

    const allTools: Tool[] = [];

    for (const { serverName, client, tools } of connected) {
      for (const tool of tools) {
        const isColliding = (nameCounts.get(tool.name) ?? 1) > 1;
        const exposedName = isColliding ? `${serverName}__${tool.name}` : tool.name;

        this.routingTable.set(exposedName, {
          client,
          originalName: tool.name,
          serverName,
        });

        allTools.push({ ...tool, name: exposedName });
      }
    }

    this._aggregatedTools = allTools;
    process.stderr.write(
      `[Sift] Aggregated ${allTools.length} tool(s) from ${connected.length} upstream(s).\n`
    );
  }
}
