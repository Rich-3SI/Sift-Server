/**
 * Health + admin HTTP listener for Sift Server.
 *
 *   GET /healthz  → 200 once the process is up (liveness)
 *   GET /readyz   → 200 when the upstream pool is connected (readiness)
 *   GET /stats    → JSON snapshot of server counters (consumed by dashboard + ops)
 *   GET /sessions → JSON array of active sessions (admin — intended for trusted networks)
 *
 * Listens on a separate port from the MCP endpoint so operators can restrict
 * /stats and /sessions to an internal network.
 */

import { createServer, type IncomingMessage, type ServerResponse, type Server as HttpServer } from "node:http";
import type { UpstreamPool } from "../../src/upstream-pool.js";
import type { ConfigStore } from "../../src/config-store.js";
import type { SiftServer } from "./server.js";
import { adminAuth, handleAdmin } from "./admin.js";

export function startHealthServer(
  port: number,
  pool: UpstreamPool,
  server: SiftServer,
  configStore?: ConfigStore
): HttpServer {
  const http = createServer((req, res) => {
    void (async () => {
      // Admin routes (mutating, authenticated) get first crack.
      if (configStore && await handleAdmin(req, res, {
        configStore,
        disconnectSession: (sessionId) => server.disconnectSession(sessionId),
        simulateToolCall: (request) => server.simulateToolCall(request),
      })) return;
      routeHealth(req, res, pool, server);
    })().catch((err: unknown) => {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: String(err) }));
    });
  });

  http.listen(port, "0.0.0.0", () => {
    process.stderr.write(`[Sift Server] Admin endpoints on http://0.0.0.0:${port}/healthz\n`);
  });
  http.unref();
  return http;
}

function routeHealth(
  req: IncomingMessage,
  res: ServerResponse,
  pool: UpstreamPool,
  server: SiftServer
): void {
  const url = req.url ?? "";
  if (url === "/healthz") {
    json(res, 200, { status: "alive" });
    return;
  }
  if (url === "/readyz") {
    if (pool.allReady) {
      json(res, 200, { status: "ready" });
    } else {
      json(res, 503, { status: "not-ready" });
    }
    return;
  }
  if (url === "/stats") {
    if (!adminAuth(req)) {
      json(res, 401, { error: "Admin auth required" });
      return;
    }
    json(res, 200, server.stats());
    return;
  }
  if (url === "/sessions") {
    if (!adminAuth(req)) {
      json(res, 401, { error: "Admin auth required" });
      return;
    }
    json(res, 200, { sessions: server.listSessions() });
    return;
  }
  json(res, 404, { error: "Not found" });
}

function json(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}
