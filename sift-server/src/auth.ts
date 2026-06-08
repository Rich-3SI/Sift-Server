/**
 * Authentication layer for sift-server.
 *
 * Maps a client-presented bearer token to a TenantContext that carries
 * userId / orgId / optional email through the security evaluation pipeline.
 *
 * Supports static API keys for simple deployments and JWT/OIDC bearer tokens
 * for identity providers.
 */

import {
  createHmac,
  createPublicKey,
  createVerify,
  timingSafeEqual,
  type JsonWebKey,
} from "node:crypto";
import type { IncomingMessage } from "node:http";
import type { ApiKeyEntry, JwtAuthConfig, TenantContext } from "./types.js";

type JwtHeader = {
  alg?: string;
  kid?: string;
  typ?: string;
};

type JwtPayload = Record<string, unknown> & {
  iss?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  sub?: string;
};

type CachedJwks = {
  fetchedAt: number;
  keys: JsonWebKey[];
};

export type ApiKeyIndexEntry = TenantContext & {
  expiresAtMs?: number;
};

const jwksCache = new Map<string, CachedJwks>();

/**
 * Build an index from bearer token → TenantContext for O(1) lookup.
 * Call once at startup; pass the returned map to validateApiKey().
 */
export function buildKeyIndex(keys: ApiKeyEntry[]): Map<string, ApiKeyIndexEntry> {
  const index = new Map<string, ApiKeyIndexEntry>();
  const now = Date.now();
  for (const k of keys) {
    if (k.revoked === true) continue;
    const expiresAtMs = k.expiresAt ? Date.parse(k.expiresAt) : undefined;
    if (expiresAtMs !== undefined && expiresAtMs <= now) continue;
    index.set(k.key, {
      userId: k.userId,
      orgId: k.orgId,
      email: k.email,
      description: k.description,
      expiresAtMs,
    });
  }
  return index;
}

/**
 * Pull the Bearer token out of an Authorization header.
 * Returns undefined when the header is missing or not a Bearer scheme.
 */
export function extractBearerToken(req: IncomingMessage): string | undefined {
  const raw = req.headers["authorization"];
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (!value) return undefined;
  const prefix = "Bearer ";
  if (!value.startsWith(prefix)) return undefined;
  const token = value.slice(prefix.length).trim();
  return token || undefined;
}

/**
 * Validate a presented bearer token against the key index.
 * Returns the TenantContext on success, null on failure.
 */
export function validateApiKey(
  token: string | undefined,
  keyIndex: Map<string, ApiKeyIndexEntry>
): TenantContext | null {
  if (!token) return null;
  const entry = keyIndex.get(token);
  if (!entry) return null;
  if (entry.expiresAtMs !== undefined && entry.expiresAtMs <= Date.now()) {
    keyIndex.delete(token);
    return null;
  }
  const { expiresAtMs: _expiresAtMs, ...tenant } = entry;
  return tenant;
}

export async function validateJwtToken(
  token: string | undefined,
  config: JwtAuthConfig | undefined
): Promise<TenantContext | null> {
  if (!token || !config) return null;
  if (!config.allowMissingIssuer && !config.issuer) return null;
  if (!config.allowMissingAudience && !config.audience) return null;

  const parsed = parseJwt(token);
  if (!parsed) return null;

  const { header, payload, signingInput, signature } = parsed;
  const alg = header.alg;
  if (!alg || alg.toLowerCase() === "none") return null;

  const allowedAlgorithms = config.allowedAlgorithms ?? defaultAllowedAlgorithms(config);
  if (!allowedAlgorithms.includes(alg)) return null;

  const validSignature = await verifyJwtSignature(alg, header, signingInput, signature, config);
  if (!validSignature) return null;

  if (!validateRegisteredClaims(payload, config)) return null;
  if (!validateRequiredClaims(payload, config.requiredClaims)) return null;

  const userId = getClaimString(payload, config.userIdClaim ?? "sub");
  const orgId = getClaimString(payload, config.orgIdClaim ?? "org_id") ?? config.defaultOrgId;
  if (!userId || !orgId) return null;

  return {
    userId,
    orgId,
    email: getClaimString(payload, config.emailClaim ?? "email"),
    description: `jwt:${payload.iss ?? "local"}`,
  };
}

function parseJwt(token: string): {
  header: JwtHeader;
  payload: JwtPayload;
  signingInput: string;
  signature: Buffer;
} | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  if (!encodedHeader || !encodedPayload || !encodedSignature) return null;

  try {
    const header = JSON.parse(base64urlDecode(encodedHeader).toString("utf8")) as JwtHeader;
    const payload = JSON.parse(base64urlDecode(encodedPayload).toString("utf8")) as JwtPayload;
    return {
      header,
      payload,
      signingInput: `${encodedHeader}.${encodedPayload}`,
      signature: base64urlDecode(encodedSignature),
    };
  } catch {
    return null;
  }
}

function base64urlDecode(value: string): Buffer {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(normalized.length + ((4 - (normalized.length % 4)) % 4), "=");
  return Buffer.from(padded, "base64");
}

function defaultAllowedAlgorithms(config: JwtAuthConfig): string[] {
  if (config.hmacSecret && !config.jwksUrl && !config.jwks?.length) return ["HS256"];
  if (config.hmacSecret) return ["RS256", "HS256"];
  return ["RS256"];
}

async function verifyJwtSignature(
  alg: string,
  header: JwtHeader,
  signingInput: string,
  signature: Buffer,
  config: JwtAuthConfig
): Promise<boolean> {
  if (alg === "HS256") {
    if (!config.hmacSecret) return false;
    const expected = createHmac("sha256", config.hmacSecret).update(signingInput).digest();
    return expected.length === signature.length && timingSafeEqual(expected, signature);
  }

  if (alg === "RS256") {
    const keys = await loadJwks(config);
    const jwk = selectJwk(keys, header);
    if (!jwk) return false;
    try {
      const publicKey = createPublicKey({ key: jwk, format: "jwk" });
      const verifier = createVerify("RSA-SHA256");
      verifier.update(signingInput);
      verifier.end();
      return verifier.verify(publicKey, signature);
    } catch {
      return false;
    }
  }

  return false;
}

async function loadJwks(config: JwtAuthConfig): Promise<JsonWebKey[]> {
  if (config.jwks?.length) return config.jwks;
  if (!config.jwksUrl) return [];

  const ttlMs = (config.jwksCacheTtlSeconds ?? 300) * 1000;
  const cached = jwksCache.get(config.jwksUrl);
  if (cached && Date.now() - cached.fetchedAt < ttlMs) return cached.keys;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5_000);
  try {
    const res = await fetch(config.jwksUrl, { signal: controller.signal });
    if (!res.ok) return cached?.keys ?? [];
    const body = await res.json() as { keys?: JsonWebKey[] };
    const keys = Array.isArray(body.keys) ? body.keys : [];
    jwksCache.set(config.jwksUrl, { fetchedAt: Date.now(), keys });
    return keys;
  } catch {
    return cached?.keys ?? [];
  } finally {
    clearTimeout(timeout);
  }
}

function selectJwk(keys: JsonWebKey[], header: JwtHeader): JsonWebKey | undefined {
  const signingKeys = keys.filter((key) => {
    const use = key.use as string | undefined;
    const alg = key.alg as string | undefined;
    return (!use || use === "sig") && (!alg || alg === header.alg);
  });

  if (header.kid) {
    return signingKeys.find((key) => key.kid === header.kid);
  }
  return signingKeys[0];
}

function validateRegisteredClaims(payload: JwtPayload, config: JwtAuthConfig): boolean {
  const now = Math.floor(Date.now() / 1000);
  const tolerance = config.clockToleranceSeconds ?? 60;

  if (payload.exp === undefined) {
    if (!config.allowMissingExpiration) return false;
  } else if (typeof payload.exp !== "number") {
    return false;
  } else if (payload.exp <= now - tolerance) {
    return false;
  }
  if (payload.nbf !== undefined && typeof payload.nbf !== "number") return false;
  if (typeof payload.nbf === "number" && payload.nbf > now + tolerance) return false;
  if (config.issuer && payload.iss !== config.issuer) return false;
  if (config.audience && !audienceMatches(payload.aud, config.audience)) return false;

  return true;
}

function audienceMatches(tokenAudience: string | string[] | undefined, expected: string | string[]): boolean {
  if (!tokenAudience) return false;
  const tokenAudiences = Array.isArray(tokenAudience) ? tokenAudience : [tokenAudience];
  const expectedAudiences = Array.isArray(expected) ? expected : [expected];
  return expectedAudiences.some((aud) => tokenAudiences.includes(aud));
}

function validateRequiredClaims(
  payload: JwtPayload,
  requiredClaims: JwtAuthConfig["requiredClaims"]
): boolean {
  if (!requiredClaims) return true;
  for (const [claim, expected] of Object.entries(requiredClaims)) {
    const actual = getClaim(payload, claim);
    const allowed = Array.isArray(expected) ? expected : [expected];
    if (typeof actual !== "string" || !allowed.includes(actual)) return false;
  }
  return true;
}

function getClaimString(payload: JwtPayload, claim: string): string | undefined {
  const value = getClaim(payload, claim);
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function getClaim(payload: JwtPayload, claim: string): unknown {
  if (Object.prototype.hasOwnProperty.call(payload, claim)) return payload[claim];
  if (!claim.includes(".")) return undefined;

  let current: unknown = payload;
  for (const part of claim.split(".")) {
    if (current === null || typeof current !== "object") return undefined;
    current = (current as Record<string, unknown>)[part];
  }
  return current;
}
