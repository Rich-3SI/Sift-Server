import { createHmac } from "crypto";
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "fs";
import { join } from "path";
import { homedir } from "os";
import type { AllowedUsersConfig, GroupConfig, PolicySet } from "./config-store.js";

export const SIFT_DIR = join(homedir(), ".sift");
export const POLICY_CACHE_PATH = join(SIFT_DIR, "policy-cache.json");

export interface PolicyCachePayload {
  syncedAt: string;
  defaultPolicy?: PolicySet;
  groups?: Record<string, GroupConfig>;
  userGroups?: Record<string, string>;
  allowedUsers?: AllowedUsersConfig;
}

export type PolicyCache = PolicyCachePayload;

export interface SignedPolicyCache extends PolicyCachePayload {
  signature: string;
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }

  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, entryValue]) => entryValue !== undefined)
    .sort(([a], [b]) => a.localeCompare(b));

  return `{${entries
    .map(([key, entryValue]) => `${JSON.stringify(key)}:${stableStringify(entryValue)}`)
    .join(",")}}`;
}

export function signPolicyCache(payload: PolicyCachePayload, secret: string): string {
  return createHmac("sha256", secret)
    .update(stableStringify(payload))
    .digest("hex");
}

export function writeSignedPolicyCache(payload: PolicyCachePayload, secret: string): void {
  mkdirSync(SIFT_DIR, { recursive: true });
  const signed: SignedPolicyCache = {
    ...payload,
    signature: signPolicyCache(payload, secret),
  };
  writeFileSync(POLICY_CACHE_PATH, JSON.stringify(signed, null, 2) + "\n");
}

export function verifySignedPolicyCache(
  raw: string,
  secret: string
): { ok: true; cache: SignedPolicyCache } | { ok: false; reason: string } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { ok: false, reason: "invalid JSON" };
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { ok: false, reason: "invalid cache shape" };
  }

  const candidate = parsed as Partial<SignedPolicyCache>;
  if (typeof candidate.signature !== "string" || candidate.signature.length === 0) {
    return { ok: false, reason: "missing signature" };
  }

  const { signature, ...payload } = candidate;
  const expected = signPolicyCache(payload as PolicyCachePayload, secret);
  if (signature !== expected) {
    return { ok: false, reason: "signature mismatch" };
  }

  return { ok: true, cache: candidate as SignedPolicyCache };
}

export function readVerifiedPolicyCache(
  secret: string
): { ok: true; cache: SignedPolicyCache } | { ok: false; reason: string } {
  if (!existsSync(POLICY_CACHE_PATH)) {
    return { ok: false, reason: "cache missing" };
  }

  try {
    const raw = readFileSync(POLICY_CACHE_PATH, "utf-8");
    return verifySignedPolicyCache(raw, secret);
  } catch {
    return { ok: false, reason: "cache unreadable" };
  }
}
