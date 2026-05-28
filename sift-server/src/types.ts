/**
 * Shared types for Sift Server.
 */

import type { JsonWebKey } from "node:crypto";

/**
 * Tenant context resolved from an incoming request's API key.
 * Passed through the security evaluation pipeline so the SecurityEngine
 * can apply per-user rules and audit handlers can attribute activity.
 */
export interface TenantContext {
  /** Identifier of the user whose API key was presented. */
  userId: string;
  /** Organization ID — included in audit rows and policy context. */
  orgId: string;
  /** Optional email for allowed-users enforcement. */
  email?: string;
  /** Free-form label (e.g. "Engineering read-only"). */
  description?: string;
}

/**
 * An API key entry in the sift-server config.
 * Static keys defined in config.
 */
export interface ApiKeyEntry {
  /** Opaque bearer token presented by the client. */
  key: string;
  /** Maps to TenantContext. */
  userId: string;
  orgId: string;
  email?: string;
  description?: string;
  /** ISO timestamp after which the key is ignored at startup. */
  expiresAt?: string;
  /** Revoked keys stay in config for auditability but are not accepted. */
  revoked?: boolean;
}

/** JWT/OIDC bearer-token validation settings. */
export interface JwtAuthConfig {
  /** Expected token issuer (`iss`). Optional for local/dev JWTs. */
  issuer?: string;
  /** Expected token audience (`aud`). Optional when your IdP omits audience. */
  audience?: string | string[];
  /** Remote JWKS endpoint for RS256-signed tokens. */
  jwksUrl?: string;
  /** Inline JWKS keys for air-gapped or test deployments. */
  jwks?: JsonWebKey[];
  /** Shared secret for HS256 local/dev tokens. Prefer JWKS/RS256 in production. */
  hmacSecret?: string;
  /** Allowed JWT algorithms. Defaults to HS256 when hmacSecret is set, otherwise RS256. */
  allowedAlgorithms?: string[];
  /** Claim names used to build TenantContext. */
  userIdClaim?: string;
  orgIdClaim?: string;
  emailClaim?: string;
  /** Fallback org when tokens do not carry an org claim. */
  defaultOrgId?: string;
  /** Extra claims that must match exactly or be one of the listed values. */
  requiredClaims?: Record<string, string | string[]>;
  /** Clock skew allowance in seconds. Defaults to 60. */
  clockToleranceSeconds?: number;
  /** JWKS cache TTL in seconds. Defaults to 300. */
  jwksCacheTtlSeconds?: number;
}

/** Info about an active per-client session. */
export interface SessionInfo {
  sessionId: string;
  userId: string;
  orgId: string;
  createdAt: number;
  lastActivity: number;
  toolCalls: number;
}

/** Statistics snapshot for health and admin endpoints. */
export interface ServerStats {
  activeSessions: number;
  upstreamCount: number;
  toolCallsTotal: number;
  toolCallsBlocked: number;
  startedAt: string;
}
