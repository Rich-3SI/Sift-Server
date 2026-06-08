/**
 * SiftServer — the core firewall proxy.
 *
 * Architecture (server-side, the inverse of src/proxy.ts which is client-side):
 *
 *   MCP Client  ──POST /mcp──▶  SiftServer HTTP listener
 *                                    │
 *                                    ├─ validate Bearer token → TenantContext
 *                                    ├─ create/reuse session (StreamableHTTPServerTransport + MCP Server)
 *                                    ├─ on CallToolRequest:
 *                                    │     • SecurityEngine.evaluateInput()
 *                                    │     • pool.route() → upstream Client
 *                                    │     • forward tool call
 *                                    │     • SecurityEngine.inspectOutput()
 *                                    │     • audit (console + SQLite + optional exports)
 *                                    └─ return result
 *
 * Key differences from SiftProxy (src/proxy.ts):
 *   • UpstreamPool is SHARED across all sessions (SiftProxy created one per session).
 *   • SecurityEngine is SHARED, with rate/blast counters scoped by tenant/session.
 *   • Each session is created from a bearer token → TenantContext; rules are
 *     resolved per-user via ConfigStore.resolveRules(userId).
 *   • Audit entries carry orgId so downstream exports can preserve tenant context.
 */

import { createServer, type IncomingMessage, type Server as HttpServer, type ServerResponse } from "node:http";
import { randomUUID } from "node:crypto";
import { Server as McpServer } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
  ListResourcesRequestSchema,
  ListResourceTemplatesRequestSchema,
  ReadResourceRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
  type CallToolResult,
  type GetPromptResult,
  type ReadResourceResult,
} from "@modelcontextprotocol/sdk/types.js";

import { SecurityEngine, type GenericToolCall } from "../../src/engine.js";
import { containsPii, detectInjection } from "../../src/rules/index.js";
import type { AuditHandler, AuditEntry } from "../../src/audit.js";
import type { ConfigStore } from "../../src/config-store.js";
import type { UpstreamPool } from "../../src/upstream-pool.js";
import {
  scanMetadataItems,
  scanMetadataValue,
  shouldBlockMetadata,
  type MetadataKind,
  type MetadataScanFinding,
} from "../../src/metadata-scan.js";

import type { ResolvedServerOptions } from "./config.js";
import type { SessionInfo, TenantContext, ServerStats } from "./types.js";
import { buildKeyIndex, extractBearerToken, validateApiKey, validateJwtToken, type ApiKeyIndexEntry } from "./auth.js";

export interface SiftServerOptions {
  configStore: ConfigStore;
  pool: UpstreamPool;
  auditHandler: AuditHandler;
  options: ResolvedServerOptions;
}

export interface PolicySimulationRequest {
  tool: string;
  input?: Record<string, unknown>;
  userId?: string;
  orgId?: string;
  sessionId?: string;
  clientName?: string;
}

interface SessionEntry {
  mcp: McpServer;
  transport: StreamableHTTPServerTransport;
  tenant: TenantContext;
  createdAt: number;
  lastActivity: number;
  toolCalls: number;
}

const SWEEP_INTERVAL_MS = 60_000;

export class SiftServer {
  private readonly configStore: ConfigStore;
  private readonly pool: UpstreamPool;
  private readonly auditHandler: AuditHandler;
  private readonly opts: ResolvedServerOptions;
  private readonly engine: SecurityEngine;
  private readonly keyIndex: Map<string, ApiKeyIndexEntry>;
  private readonly sessions = new Map<string, SessionEntry>();
  private httpServer: HttpServer | null = null;
  private sweepTimer: NodeJS.Timeout | null = null;
  private readonly startedAt = new Date().toISOString();

  // Lightweight counters for health and admin status.
  private toolCallsTotal = 0;
  private toolCallsBlocked = 0;

  constructor(opts: SiftServerOptions) {
    this.configStore = opts.configStore;
    this.pool = opts.pool;
    this.auditHandler = opts.auditHandler;
    this.opts = opts.options;
    this.keyIndex = buildKeyIndex(this.opts.apiKeys);

    this.engine = new SecurityEngine({
      getRules: (userId) => this.configStore.resolveRules(userId),
      // SiftServer handles its own audit dispatch via auditWithOrg() so the
      // entry can carry orgId (which GenericToolCall does not). The engine's
      // own audit() method is never called here, so this onAudit is a noop.
      onAudit: async () => {},
      blastRadiusLimit: this.opts.blastRadiusLimit,
      rateLimitPerMinute: this.opts.rateLimitPerMinute,
    });
  }

  // ── Public API ─────────────────────────────────────────────────────────────

  /** Bind the HTTP listener. Returns once the server is accepting connections. */
  async start(): Promise<void> {
    this.httpServer = createServer((req, res) => {
      this.handleRequest(req, res).catch((err: unknown) => {
        process.stderr.write(`[Sift Server] Request error: ${String(err)}\n`);
        if (!res.headersSent) {
          res.writeHead(500, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Internal server error" }));
        }
      });
    });

    await new Promise<void>((resolve, reject) => {
      this.httpServer!.listen(this.opts.port, this.opts.host, () => resolve());
      this.httpServer!.on("error", reject);
    });

    this.sweepTimer = setInterval(() => this.sweepIdleSessions(), SWEEP_INTERVAL_MS);
    this.sweepTimer.unref();

    process.stderr.write(
      `[Sift Server] Listening on http://${this.opts.host}:${this.opts.port}/mcp — ` +
        `${this.pool.getAggregatedTools().length} tool(s) across ${this.countUpstreams()} upstream(s).\n`
    );
  }

  /** Close the HTTP listener and all active sessions. */
  async stop(): Promise<void> {
    if (this.sweepTimer) clearInterval(this.sweepTimer);
    for (const [id, session] of this.sessions) {
      try {
        await session.transport.close();
      } catch {
        /* ignore */
      }
      this.sessions.delete(id);
    }
    if (this.httpServer) {
      await new Promise<void>((resolve) => this.httpServer!.close(() => resolve()));
    }
  }

  /** Snapshot of currently-tracked stats for health and admin endpoints. */
  stats(): ServerStats {
    return {
      activeSessions: this.sessions.size,
      upstreamCount: this.countUpstreams(),
      toolCallsTotal: this.toolCallsTotal,
      toolCallsBlocked: this.toolCallsBlocked,
      startedAt: this.startedAt,
    };
  }

  /** Session list for admin endpoints. */
  listSessions(): SessionInfo[] {
    return Array.from(this.sessions.entries()).map(([sessionId, s]) => ({
      sessionId,
      userId: s.tenant.userId,
      orgId: s.tenant.orgId,
      createdAt: s.createdAt,
      lastActivity: s.lastActivity,
      toolCalls: s.toolCalls,
    }));
  }

  /** Disconnect a live MCP session by ID. Used by the admin API. */
  disconnectSession(sessionId: string): boolean {
    const session = this.sessions.get(sessionId);
    if (!session) return false;
    this.sessions.delete(sessionId);
    try {
      void session.transport.close();
    } catch {
      /* ignore */
    }
    process.stderr.write(`[Sift Server] Session disconnected by admin: ${sessionId}\n`);
    return true;
  }

  simulateToolCall(request: PolicySimulationRequest): unknown {
    const input = request.input ?? {};
    const route = this.pool.route(request.tool);
    const originalToolName = route?.originalName ?? request.tool;
    const call: GenericToolCall = {
      tool: request.tool,
      originalTool: route?.originalName,
      upstreamName: route?.serverName,
      input,
      protocol: "mcp",
      userId: request.userId ?? "simulation",
      orgId: request.orgId ?? "simulation",
      sessionId: request.sessionId ?? "simulation",
      clientName: request.clientName ?? (route ? `sift-server/${route.serverName}` : "sift-server/simulation"),
    };
    const result = this.engine.simulateInput(call);
    return {
      knownTool: Boolean(route),
      exposedToolName: request.tool,
      originalToolName,
      route: route ? { upstream: route.serverName } : null,
      ...result,
    };
  }

  // ── HTTP request handler ───────────────────────────────────────────────────

  private async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.url !== "/mcp" && req.url !== "/mcp/") {
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Not found. Use POST /mcp" }));
      return;
    }

    // Existing session — route to its transport.
    const sessionId = req.headers["mcp-session-id"] as string | undefined;
    if (sessionId) {
      const tenant = await this.authenticate(req);
      if (!tenant) {
        this.writeUnauthorized(res);
        return;
      }
      const session = this.sessions.get(sessionId);
      if (!session) {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Session not found" }));
        return;
      }
      if (!sameTenant(session.tenant, tenant)) {
        res.writeHead(403, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Session tenant mismatch" }));
        return;
      }
      if (!this.configStore.isUserAllowed(tenant.email)) {
        res.writeHead(403, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            error: "Access denied. User is not authorized to use tools.",
          })
        );
        return;
      }
      session.lastActivity = Date.now();
      await session.transport.handleRequest(req, res);
      return;
    }

    // New session — only on POST (initialize).
    if (req.method !== "POST") {
      res.writeHead(405, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Method not allowed" }));
      return;
    }

    // Auth.
    const tenant = await this.authenticate(req);
    if (!tenant) {
      this.writeUnauthorized(res);
      return;
    }

    // Capacity.
    if (this.sessions.size >= this.opts.maxSessions) {
      res.writeHead(503, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Too many active sessions" }));
      return;
    }

    // Allowed-users enforcement (applies when enabled in ConfigStore).
    if (!this.configStore.isUserAllowed(tenant.email)) {
      res.writeHead(403, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          error: "Access denied. User is not authorized to use tools.",
        })
      );
      return;
    }

    await this.createSessionAndHandle(req, res, tenant);
  }

  private async authenticate(req: IncomingMessage): Promise<TenantContext | null> {
    if (this.opts.authMode === "none") {
      return { userId: "anonymous", orgId: "anonymous" };
    }
    const token = extractBearerToken(req);
    if (this.opts.authMode === "api-key") {
      return validateApiKey(token, this.keyIndex);
    }
    if (this.opts.authMode === "jwt") {
      return validateJwtToken(token, this.opts.jwt);
    }
    const apiKeyTenant = validateApiKey(token, this.keyIndex);
    if (apiKeyTenant) return apiKeyTenant;
    return validateJwtToken(token, this.opts.jwt);
  }

  // ── Session lifecycle ──────────────────────────────────────────────────────

  private async createSessionAndHandle(
    req: IncomingMessage,
    res: ServerResponse,
    tenant: TenantContext
  ): Promise<void> {
    const newSessionId = randomUUID();
    const now = Date.now();

    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => newSessionId,
    });

    transport.onclose = () => {
      this.sessions.delete(newSessionId);
      process.stderr.write(
        `[Sift Server] Session closed: ${newSessionId} (user: ${tenant.userId})\n`
      );
    };

    const mcp = new McpServer(
      { name: "sift-server", version: "0.1.0" },
      { capabilities: { tools: {}, resources: {}, prompts: {}, logging: {} } }
    );

    const session: SessionEntry = {
      mcp,
      transport,
      tenant,
      createdAt: now,
      lastActivity: now,
      toolCalls: 0,
    };
    this.sessions.set(newSessionId, session);

    this.registerHandlers(mcp, session, newSessionId);
    await mcp.connect(transport);

    process.stderr.write(
      `[Sift Server] New session: ${newSessionId} (user: ${tenant.userId}, org: ${tenant.orgId})\n`
    );

    await transport.handleRequest(req, res);
  }

  private registerHandlers(
    mcp: McpServer,
    session: SessionEntry,
    sessionId: string
  ): void {
    mcp.setRequestHandler(ListToolsRequestSchema, async () => {
      await this.pool.waitForAll();
      // Strip fields that some clients fail to validate — mirrors src/proxy.ts behaviour.
      const safeTools = this.pool
        .getAggregatedTools()
        .map(({ outputSchema: _o, execution: _e, ...rest }) => rest);
      return {
        tools: await this.scanMetadataList("tool", safeTools, session.tenant, sessionId),
      };
    });

    mcp.setRequestHandler(CallToolRequestSchema, async (request) => {
      await this.pool.waitForAll();
      session.lastActivity = Date.now();
      session.toolCalls += 1;
      const { name, arguments: callArgs } = request.params;
      return this.handleToolCall(
        session.tenant,
        sessionId,
        name,
        (callArgs ?? {}) as Record<string, unknown>
      );
    });

    mcp.setRequestHandler(ListResourcesRequestSchema, async () => {
      await this.pool.waitForAll();
      const resources = await this.pool.listResources();
      return {
        resources: await this.scanMetadataList("resource", resources, session.tenant, sessionId),
      };
    });
    mcp.setRequestHandler(ListResourceTemplatesRequestSchema, async () => {
      await this.pool.waitForAll();
      const resourceTemplates = await this.pool.listResourceTemplates();
      return {
        resourceTemplates: await this.scanMetadataList(
          "resource-template",
          resourceTemplates,
          session.tenant,
          sessionId
        ),
      };
    });
    mcp.setRequestHandler(ReadResourceRequestSchema, async (request) => {
      await this.pool.waitForAll();
      session.lastActivity = Date.now();
      return this.handleResourceRead(session.tenant, sessionId, request.params.uri);
    });
    mcp.setRequestHandler(ListPromptsRequestSchema, async () => {
      await this.pool.waitForAll();
      const prompts = await this.pool.listPrompts();
      return {
        prompts: await this.scanMetadataList("prompt", prompts, session.tenant, sessionId),
      };
    });
    mcp.setRequestHandler(GetPromptRequestSchema, async (request) => {
      await this.pool.waitForAll();
      session.lastActivity = Date.now();
      return this.handlePromptGet(
        session.tenant,
        sessionId,
        request.params.name,
        request.params.arguments
      );
    });
  }

  private async scanMetadataList<T>(
    kind: MetadataKind,
    items: T[],
    tenant: TenantContext,
    sessionId: string
  ): Promise<T[]> {
    const result = scanMetadataItems(kind, items, this.opts.metadataScan);
    await this.auditMetadataFindings(tenant, sessionId, kind, result.findings);
    if (result.blockedCount > 0) {
      process.stderr.write(
        `[Sift Server] Blocked ${result.blockedCount} unsafe MCP ${kind} metadata item(s).\n`
      );
    }
    return result.items;
  }

  private async scanMetadataObject<T>(
    kind: MetadataKind,
    value: T,
    tenant: TenantContext,
    sessionId: string
  ): Promise<T> {
    const findings = scanMetadataValue(kind, value, this.opts.metadataScan);
    await this.auditMetadataFindings(tenant, sessionId, kind, findings);
    if (shouldBlockMetadata(findings, this.opts.metadataScan)) {
      throw new Error(`[Sift Server] Blocked unsafe MCP ${kind} metadata`);
    }
    return value;
  }

  // ── Tool call handling ─────────────────────────────────────────────────────

  private async handleToolCall(
    tenant: TenantContext,
    sessionId: string,
    toolName: string,
    input: Record<string, unknown>
  ): Promise<CallToolResult> {
    const startTime = Date.now();

    const route = this.pool.route(toolName);
    if (!route) {
      await this.auditUnknownTool(tenant, sessionId, toolName, input, Date.now() - startTime);
      return {
        content: [{ type: "text", text: `[Sift Server] Unknown tool: ${toolName}` }],
        isError: true,
      };
    }

    const call: GenericToolCall = {
      tool: toolName,
      originalTool: route.originalName,
      upstreamName: route.serverName,
      input,
      protocol: "mcp",
      userId: tenant.userId,
      orgId: tenant.orgId,
      sessionId,
      clientName: `sift-server/${route.serverName}`,
    };

    const verdict = this.engine.evaluateInput(call);

    if (verdict.action === "block") {
      const outputInspection = this.engine.inspectOutput(null, verdict);
      await this.auditWithOrg(
        call,
        verdict,
        null,
        outputInspection,
        Date.now() - startTime,
        tenant.orgId
      );
      return {
        content: [{ type: "text", text: `[Sift Server] ${verdict.blockReason}` }],
        isError: true,
      };
    }

    try {
      const forwardInput = verdict.sanitizedInput ?? input;
      const upstreamResult = await route.client.callTool({
        name: route.originalName,
        arguments: forwardInput,
      });

      const outputInspection = this.engine.inspectOutput(upstreamResult, verdict);
      await this.auditWithOrg(
        call,
        verdict,
        upstreamResult,
        outputInspection,
        Date.now() - startTime,
        tenant.orgId
      );

      const finalResult = outputInspection.sanitizedOutput ?? upstreamResult;
      const resultContent = (finalResult as { content?: Array<{ type: string; text?: string }> })
        .content;

      if (Array.isArray(resultContent) && resultContent.length > 0) {
        return {
          content: resultContent.map((item) => ({
            type: "text" as const,
            text: item.text ?? JSON.stringify(item),
          })),
          isError: (upstreamResult as { isError?: boolean }).isError === true,
        };
      }

      return { content: [{ type: "text", text: JSON.stringify(finalResult) }] };
    } catch (err) {
      const errMsg = String(err);
      const outputInspection = this.engine.inspectOutput({ error: errMsg }, verdict);
      await this.auditWithOrg(
        call,
        verdict,
        { error: errMsg },
        outputInspection,
        Date.now() - startTime,
        tenant.orgId
      );
      return {
        content: [{ type: "text", text: `[Sift Server] Upstream error: ${this.safeErrorText(errMsg, outputInspection)}` }],
        isError: true,
      };
    }
  }

  private async handleResourceRead(
    tenant: TenantContext,
    sessionId: string,
    uri: string
  ): Promise<ReadResourceResult> {
    const startTime = Date.now();
    const input = { uri };
    const call: GenericToolCall = {
      tool: "mcp.read_resource",
      input,
      protocol: "mcp",
      userId: tenant.userId,
      orgId: tenant.orgId,
      sessionId,
      clientName: "sift-server/resource",
    };
    const verdict = this.engine.evaluateInput(call);

    if (verdict.action === "block") {
      const outputInspection = this.engine.inspectOutput(null, verdict);
      await this.auditWithOrg(call, verdict, null, outputInspection, Date.now() - startTime, tenant.orgId);
      throw new Error(`[Sift Server] ${verdict.blockReason}`);
    }

    try {
      const forwardInput = verdict.sanitizedInput ?? input;
      const forwardUri = typeof forwardInput.uri === "string" ? forwardInput.uri : uri;
      const upstreamResult = await this.pool.readResource(forwardUri);
      const outputInspection = this.engine.inspectOutput(upstreamResult, verdict);
      await this.auditWithOrg(
        call,
        verdict,
        upstreamResult,
        outputInspection,
        Date.now() - startTime,
        tenant.orgId
      );
      const finalResult = outputInspection.sanitizedOutput ?? upstreamResult;
      return this.scanMetadataObject("resource-result", finalResult as ReadResourceResult, tenant, sessionId);
    } catch (err) {
      const errMsg = String(err);
      const outputInspection = this.engine.inspectOutput({ error: errMsg }, verdict);
      await this.auditWithOrg(
        call,
        verdict,
        { error: errMsg },
        outputInspection,
        Date.now() - startTime,
        tenant.orgId
      );
      throw new Error(`[Sift Server] Resource error: ${this.safeErrorText(errMsg, outputInspection)}`);
    }
  }

  private async handlePromptGet(
    tenant: TenantContext,
    sessionId: string,
    name: string,
    args?: Record<string, string>
  ): Promise<GetPromptResult> {
    const startTime = Date.now();
    const input = { name, arguments: args ?? {} };
    const call: GenericToolCall = {
      tool: "mcp.get_prompt",
      input,
      protocol: "mcp",
      userId: tenant.userId,
      orgId: tenant.orgId,
      sessionId,
      clientName: "sift-server/prompt",
    };
    const verdict = this.engine.evaluateInput(call);

    if (verdict.action === "block") {
      const outputInspection = this.engine.inspectOutput(null, verdict);
      await this.auditWithOrg(call, verdict, null, outputInspection, Date.now() - startTime, tenant.orgId);
      throw new Error(`[Sift Server] ${verdict.blockReason}`);
    }

    try {
      const forwardInput = verdict.sanitizedInput ?? input;
      const forwardName = typeof forwardInput.name === "string" ? forwardInput.name : name;
      const forwardArgs = isStringRecord(forwardInput.arguments) ? forwardInput.arguments : args;
      const upstreamResult = await this.pool.getPrompt(forwardName, forwardArgs);
      const outputInspection = this.engine.inspectOutput(upstreamResult, verdict);
      await this.auditWithOrg(
        call,
        verdict,
        upstreamResult,
        outputInspection,
        Date.now() - startTime,
        tenant.orgId
      );
      const finalResult = outputInspection.sanitizedOutput ?? upstreamResult;
      return this.scanMetadataObject("prompt-result", finalResult as GetPromptResult, tenant, sessionId);
    } catch (err) {
      const errMsg = String(err);
      const outputInspection = this.engine.inspectOutput({ error: errMsg }, verdict);
      await this.auditWithOrg(
        call,
        verdict,
        { error: errMsg },
        outputInspection,
        Date.now() - startTime,
        tenant.orgId
      );
      throw new Error(`[Sift Server] Prompt error: ${this.safeErrorText(errMsg, outputInspection)}`);
    }
  }

  // ── Helpers ────────────────────────────────────────────────────────────────

  private writeUnauthorized(res: ServerResponse): void {
    res.writeHead(401, {
      "Content-Type": "application/json",
      "WWW-Authenticate": `Bearer realm="sift-server"`,
    });
    res.end(JSON.stringify({ error: "Unauthorized" }));
  }

  private safeErrorText(
    errMsg: string,
    inspection: ReturnType<SecurityEngine["inspectOutput"]>
  ): string {
    const sanitized = inspection.sanitizedOutput;
    if (sanitized && typeof sanitized === "object") {
      const value = (sanitized as Record<string, unknown>)["error"];
      if (typeof value === "string") return value;
    }
    return errMsg;
  }

  private async auditUnknownTool(
    tenant: TenantContext,
    sessionId: string,
    toolName: string,
    input: Record<string, unknown>,
    durationMs: number
  ): Promise<void> {
    const call: GenericToolCall = {
      tool: toolName,
      input,
      protocol: "mcp",
      userId: tenant.userId,
      orgId: tenant.orgId,
      sessionId,
      clientName: "sift-server/unknown",
    };
    const verdict = {
      id: randomUUID(),
      action: "block" as const,
      triggeredRules: ["unknown-tool"],
      piiDetected: containsPii(input),
      injectionDetected: detectInjection(input).detected,
      blockReason: `Unknown tool: ${toolName}`,
    };
    const output = { error: `Unknown tool: ${toolName}` };
    const outputInspection = this.engine.inspectOutput(output, verdict);
    await this.auditWithOrg(call, verdict, output, outputInspection, durationMs, tenant.orgId);
  }

  private async auditMetadataFindings(
    tenant: TenantContext,
    sessionId: string,
    kind: MetadataKind,
    findings: MetadataScanFinding[]
  ): Promise<void> {
    if (findings.length === 0) return;
    const action = this.opts.metadataScan.action === "block" ? "block" : "allow";
    const entry: AuditEntry = {
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      tool: `mcp.metadata.${kind}`,
      input: { kind, findings },
      output: null,
      action,
      triggeredRules: [
        ...new Set(findings.flatMap((finding) => [
          ...(finding.injectionDetected ? ["metadata-injection"] : []),
          ...(finding.piiDetected ? ["metadata-pii"] : []),
        ])),
      ],
      durationMs: 0,
      piiDetected: findings.some((finding) => finding.piiDetected),
      injectionDetected: findings.some((finding) => finding.injectionDetected),
      userId: tenant.userId,
      orgId: tenant.orgId,
      sessionId,
      clientName: "sift-server/metadata-scan",
    };

    try {
      await this.auditHandler(entry);
    } catch (err) {
      process.stderr.write(`[Sift Server] Metadata audit write failed: ${String(err)}\n`);
    }
  }

  /**
   * SecurityEngine.audit() builds its own AuditEntry from GenericToolCall, but
   * GenericToolCall does not carry orgId. We duplicate the entry construction
   * here so audit rows keep tenant context without mutating post-facto.
   */
  private async auditWithOrg(
    call: GenericToolCall,
    verdict: ReturnType<SecurityEngine["evaluateInput"]>,
    output: unknown,
    inspection: ReturnType<SecurityEngine["inspectOutput"]>,
    durationMs: number,
    orgId: string
  ): Promise<void> {
    const entry: AuditEntry = {
      id: verdict.id,
      timestamp: new Date().toISOString(),
      tool: call.tool,
      input: verdict.sanitizedInput ?? call.input,
      output: inspection.sanitizedOutput ?? output,
      action: verdict.action,
      triggeredRules: verdict.triggeredRules,
      durationMs,
      piiDetected: verdict.piiDetected || inspection.piiDetected,
      injectionDetected: verdict.injectionDetected || inspection.injectionDetected,
      userId: call.userId,
      orgId,
      sessionId: call.sessionId,
      clientName: call.clientName,
      sequenceNumber: call.sequenceNumber,
    };

    try {
      this.toolCallsTotal += 1;
      if (entry.action === "block") this.toolCallsBlocked += 1;
      await this.auditHandler(entry);
    } catch (err) {
      process.stderr.write(`[Sift Server] Audit write failed: ${String(err)}\n`);
    }
  }

  private sweepIdleSessions(): void {
    const now = Date.now();
    for (const [id, session] of this.sessions) {
      if (now - session.lastActivity > this.opts.sessionTtlMs) {
        try {
          void session.transport.close();
        } catch {
          /* ignore */
        }
        this.sessions.delete(id);
        process.stderr.write(`[Sift Server] Session expired (idle): ${id}\n`);
      }
    }
  }

  private countUpstreams(): number {
    // Derive the count from the unique set of clients in the routing table.
    const seen = new Set<unknown>();
    for (const tool of this.pool.getAggregatedTools()) {
      const route = this.pool.route(tool.name);
      if (route) seen.add(route.client);
    }
    return seen.size;
  }
}

function sameTenant(a: TenantContext, b: TenantContext): boolean {
  return a.userId === b.userId && a.orgId === b.orgId && a.email === b.email;
}

function isStringRecord(value: unknown): value is Record<string, string> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  return Object.values(value).every((item) => typeof item === "string");
}
