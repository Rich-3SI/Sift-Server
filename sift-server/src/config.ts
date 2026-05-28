/**
 * Sift Server configuration loader and validator.
 *
 * Extends the core SiftConfig with server-specific fields:
 *   - server.port / host / adminPort (where Sift Server listens)
 *   - auth.apiKeys (static bearer tokens)
 *   - auth.jwt (OIDC/JWKS bearer tokens)
 *   - maxSessions / sessionTtlMinutes / blastRadiusLimit / rateLimitPerMinute
 */

import { readFileSync } from "node:fs";
import { resolve, isAbsolute } from "node:path";
import type { SiftConfig } from "../../src/config-store.js";
import type { ApiKeyEntry, JwtAuthConfig } from "./types.js";

export type AuthMode = "api-key" | "jwt" | "api-key-or-jwt" | "none";
export type MetadataScanAction = "warn" | "block";

export interface MetadataScanConfig {
  enabled?: boolean;
  action?: MetadataScanAction;
  includeSchemas?: boolean;
  maxStringLength?: number;
}

export interface AuditWebhookConfig {
  url: string;
  headers?: Record<string, string>;
  bearerToken?: string;
  timeoutMs?: number;
}

export interface AuditExportConfig {
  jsonlPath?: string;
  webhooks?: AuditWebhookConfig[];
}

export interface SiftServerConfig extends SiftConfig {
  server?: {
    port?: number;
    host?: string;
    adminPort?: number;
  };
  auth?: {
    mode?: AuthMode;
    apiKeys?: ApiKeyEntry[];
    jwt?: JwtAuthConfig;
  };
  audit?: AuditExportConfig;
  metadataScan?: MetadataScanConfig;
  maxSessions?: number;
  sessionTtlMinutes?: number;
  blastRadiusLimit?: number;
  rateLimitPerMinute?: number;
}

/** Resolved defaults for runtime use. */
export interface ResolvedServerOptions {
  port: number;
  host: string;
  adminPort: number;
  authMode: AuthMode;
  apiKeys: ApiKeyEntry[];
  jwt?: JwtAuthConfig;
  audit?: AuditExportConfig;
  metadataScan: Required<MetadataScanConfig>;
  maxSessions: number;
  sessionTtlMs: number;
  blastRadiusLimit: number;
  rateLimitPerMinute: number;
}

/** Default values applied when the config omits them. */
export const DEFAULTS: ResolvedServerOptions = {
  port: 8080,
  host: "0.0.0.0",
  adminPort: 8081,
  authMode: "api-key",
  apiKeys: [],
  jwt: undefined,
  audit: undefined,
  metadataScan: {
    enabled: true,
    action: "warn",
    includeSchemas: true,
    maxStringLength: 20_000,
  },
  maxSessions: 1000,
  sessionTtlMs: 30 * 60 * 1000,
  blastRadiusLimit: 10,
  rateLimitPerMinute: 60,
};

export function loadServerConfig(configPath: string): SiftServerConfig {
  const full = isAbsolute(configPath) ? configPath : resolve(process.cwd(), configPath);
  const raw = readFileSync(full, "utf8");
  const parsed = JSON.parse(raw) as SiftServerConfig;
  validateServerConfig(parsed);
  return parsed;
}

export function resolveServerOptions(cfg: SiftServerConfig): ResolvedServerOptions {
  return {
    port: cfg.server?.port ?? DEFAULTS.port,
    host: cfg.server?.host ?? DEFAULTS.host,
    adminPort: cfg.server?.adminPort ?? DEFAULTS.adminPort,
    authMode: cfg.auth?.mode ?? DEFAULTS.authMode,
    apiKeys: cfg.auth?.apiKeys ?? [],
    jwt: cfg.auth?.jwt,
    audit: cfg.audit,
    metadataScan: {
      ...DEFAULTS.metadataScan,
      ...(cfg.metadataScan ?? {}),
    },
    maxSessions: cfg.maxSessions ?? DEFAULTS.maxSessions,
    sessionTtlMs: (cfg.sessionTtlMinutes ?? 30) * 60 * 1000,
    blastRadiusLimit: cfg.blastRadiusLimit ?? DEFAULTS.blastRadiusLimit,
    rateLimitPerMinute: cfg.rateLimitPerMinute ?? DEFAULTS.rateLimitPerMinute,
  };
}

function validateServerConfig(cfg: SiftServerConfig): void {
  if (!cfg.upstreams || cfg.upstreams.length === 0) {
    throw new Error(
      "sift-server config: at least one upstream must be defined in `upstreams`."
    );
  }
  for (const u of cfg.upstreams) {
    if (!u.name) throw new Error("sift-server config: every upstream needs a `name`.");
    if (!u.command && !u.url) {
      throw new Error(
        `sift-server config: upstream "${u.name}" must have either \`command\` or \`url\`.`
      );
    }
    if (u.headers && !u.url) {
      throw new Error(
        `sift-server config: upstream "${u.name}" uses \`headers\`, which only apply to HTTP/SSE upstreams.`
      );
    }
  }
  const mode = cfg.auth?.mode ?? "api-key";
  if (!["api-key", "jwt", "api-key-or-jwt", "none"].includes(mode)) {
    throw new Error("sift-server config: auth.mode must be one of api-key, jwt, api-key-or-jwt, or none.");
  }

  if (mode === "api-key" || mode === "api-key-or-jwt") {
    const keys = cfg.auth?.apiKeys ?? [];
    if (mode === "api-key" && keys.length === 0) {
      throw new Error(
        "sift-server config: auth.mode is 'api-key' but no apiKeys are defined. " +
          "Set auth.mode to 'none' for an unauthenticated server, or add keys."
      );
    }
    const seen = new Set<string>();
    for (const k of keys) {
      if (!k.key || !k.userId || !k.orgId) {
        throw new Error(
          "sift-server config: each apiKey needs `key`, `userId`, and `orgId`."
        );
      }
      if (seen.has(k.key)) {
        throw new Error("sift-server config: duplicate apiKey value detected.");
      }
      if (k.expiresAt && Number.isNaN(Date.parse(k.expiresAt))) {
        throw new Error("sift-server config: apiKey expiresAt must be a valid ISO timestamp.");
      }
      seen.add(k.key);
    }
  }

  if (mode === "jwt" || mode === "api-key-or-jwt") {
    const jwt = cfg.auth?.jwt;
    const hasApiKeys = (cfg.auth?.apiKeys ?? []).length > 0;
    if (!jwt && mode === "jwt") {
      throw new Error("sift-server config: auth.mode is 'jwt' but auth.jwt is not configured.");
    }
    if (!jwt && mode === "api-key-or-jwt" && !hasApiKeys) {
      throw new Error("sift-server config: auth.mode is 'api-key-or-jwt' but no apiKeys or auth.jwt settings are configured.");
    }
    if (jwt) validateJwtConfig(jwt);
  }

  if (cfg.metadataScan?.action && !["warn", "block"].includes(cfg.metadataScan.action)) {
    throw new Error("sift-server config: metadataScan.action must be 'warn' or 'block'.");
  }
  if (cfg.audit?.jsonlPath !== undefined && cfg.audit.jsonlPath.trim() === "") {
    throw new Error("sift-server config: audit.jsonlPath must not be empty.");
  }
  for (const webhook of cfg.audit?.webhooks ?? []) {
    if (!webhook.url) throw new Error("sift-server config: every audit webhook needs a url.");
    try {
      // Validate early so bad exports fail loudly at startup.
      new URL(webhook.url);
    } catch {
      throw new Error(`sift-server config: invalid audit webhook URL "${webhook.url}".`);
    }
  }
}

function validateJwtConfig(jwt: JwtAuthConfig): void {
  if (!jwt.jwksUrl && !jwt.jwks?.length && !jwt.hmacSecret) {
    throw new Error("sift-server config: auth.jwt requires jwksUrl, jwks, or hmacSecret.");
  }
  if (jwt.allowedAlgorithms?.some((alg) => alg.toLowerCase() === "none")) {
    throw new Error("sift-server config: auth.jwt.allowedAlgorithms must not include 'none'.");
  }
  if (jwt.jwksUrl) {
    try {
      new URL(jwt.jwksUrl);
    } catch {
      throw new Error(`sift-server config: invalid auth.jwt.jwksUrl "${jwt.jwksUrl}".`);
    }
  }
}
