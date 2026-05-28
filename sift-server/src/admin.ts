/**
 * Admin API helpers for Sift Server.
 *
 * The health/admin HTTP listener (health.ts) delegates authenticated mutation
 * endpoints to these handlers:
 *
 *   POST /admin/disconnect/:sessionId  → terminate a specific session
 *   POST /admin/simulate → dry-run policy evaluation for a tool call
 *
 * Auth uses a shared secret in the SIFT_ADMIN_SECRET env var. When unset, the
 * admin mutation endpoints return 503 to make deployment mistakes loud.
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import type { ConfigStore } from "../../src/config-store.js";

export interface AdminHandlerOptions {
  configStore: ConfigStore;
  /** Optional callback to disconnect a session by ID. */
  disconnectSession?: (sessionId: string) => boolean;
  /** Optional callback to dry-run policy evaluation for a tool call. */
  simulateToolCall?: (request: {
    tool: string;
    input?: Record<string, unknown>;
    userId?: string;
    orgId?: string;
    sessionId?: string;
    clientName?: string;
  }) => unknown;
}

export function adminAuth(req: IncomingMessage): boolean {
  const secret = process.env["SIFT_ADMIN_SECRET"];
  if (!secret) return false;
  const header = req.headers["x-sift-admin-secret"];
  const value = Array.isArray(header) ? header[0] : header;
  return value === secret;
}

/**
 * Dispatch an admin request. Returns true if the URL matched an admin route
 * (whether it succeeded or not); false to let the caller handle the URL.
 */
export function handleAdmin(
  req: IncomingMessage,
  res: ServerResponse,
  opts: AdminHandlerOptions
): Promise<boolean> {
  return handleAdminAsync(req, res, opts);
}

async function handleAdminAsync(
  req: IncomingMessage,
  res: ServerResponse,
  opts: AdminHandlerOptions
): Promise<boolean> {
  const url = req.url ?? "";
  if (!url.startsWith("/admin/")) return false;

  if (!adminAuth(req)) {
    res.writeHead(401, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Admin auth required" }));
    return true;
  }

  if (url.startsWith("/admin/disconnect/") && req.method === "POST") {
    const sessionId = url.slice("/admin/disconnect/".length);
    const ok = opts.disconnectSession?.(sessionId) ?? false;
    res.writeHead(ok ? 200 : 404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: ok ? "disconnected" : "not-found", sessionId }));
    return true;
  }

  if (url === "/admin/simulate" && req.method === "POST") {
    if (!opts.simulateToolCall) {
      res.writeHead(503, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Policy simulation is unavailable" }));
      return true;
    }

    const body = await readJsonBody(req);
    if (!isSimulationBody(body)) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Expected JSON body with string `tool` and optional object `input`." }));
      return true;
    }

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(opts.simulateToolCall(body)));
    return true;
  }

  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "Unknown admin route" }));
  return true;
}

function readJsonBody(req: IncomingMessage, maxBytes = 1_000_000): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let raw = "";
    req.setEncoding("utf8");
    req.on("data", (chunk: string) => {
      raw += chunk;
      if (raw.length > maxBytes) {
        reject(new Error("Request body too large"));
        req.destroy();
      }
    });
    req.on("end", () => {
      try {
        resolve(raw ? JSON.parse(raw) : {});
      } catch {
        resolve(null);
      }
    });
    req.on("error", reject);
  });
}

function isSimulationBody(value: unknown): value is {
  tool: string;
  input?: Record<string, unknown>;
  userId?: string;
  orgId?: string;
  sessionId?: string;
  clientName?: string;
} {
  if (value === null || typeof value !== "object") return false;
  const body = value as Record<string, unknown>;
  if (typeof body.tool !== "string" || body.tool.length === 0) return false;
  if (body.input !== undefined && (body.input === null || typeof body.input !== "object" || Array.isArray(body.input))) return false;
  for (const key of ["userId", "orgId", "sessionId", "clientName"]) {
    if (body[key] !== undefined && typeof body[key] !== "string") return false;
  }
  return true;
}
