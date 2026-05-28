/**
 * Security Engine — protocol-agnostic policy evaluation, detection, and audit.
 *
 * This is the core abstraction that decouples Sift's security logic from any
 * specific AI protocol (MCP, OpenAI function calls, etc.). Protocol adapters
 * translate their native tool call format into GenericToolCall, run it through
 * the engine, and get back a SecurityVerdict.
 */

import { randomUUID } from "node:crypto";
import {
  type SiftRule,
  evaluateRules,
  containsPii,
  redactPii,
  redactPiiDeep,
  detectInjection,
  BlastRadiusLimiter,
} from "./rules/index.js";
import { type AuditEntry, type AuditHandler } from "./audit.js";

// ── Protocol-agnostic interfaces ─────────────────────────────────────────────

/** Normalized tool call from any AI protocol. */
export interface GenericToolCall {
  /** Tool/function name. */
  tool: string;
  /** Arguments as a JSON-serializable object. */
  input: Record<string, unknown>;
  /** Protocol that originated this call (e.g. "mcp", "openai", "anthropic"). */
  protocol: string;
  /** Optional user identity. */
  userId?: string;
  orgId?: string;
  sessionId?: string;
  clientName?: string;
  sequenceNumber?: number;
}

/** The engine's decision about a tool call. */
export interface SecurityVerdict {
  /** What to do: allow, block, or redact. */
  action: "allow" | "block" | "redact";
  /** Which rules matched. */
  triggeredRules: string[];
  /** PII detected in input? */
  piiDetected: boolean;
  /** Injection patterns detected in input? */
  injectionDetected: boolean;
  /** If action=redact, the sanitized input. */
  sanitizedInput?: Record<string, unknown>;
  /** If blocked, the reason string. */
  blockReason?: string;
  /** Unique ID for this evaluation (used for audit correlation). */
  id: string;
}

/** Result after inspecting the tool output (post-execution). */
export interface OutputInspection {
  piiDetected: boolean;
  injectionDetected: boolean;
  /** If the verdict was "redact", the sanitized output. */
  sanitizedOutput?: unknown;
}

export interface SecuritySimulationResult {
  verdict: SecurityVerdict;
  skippedChecks: string[];
}

// ── Rate limiter ─────────────────────────────────────────────────────────────

interface RateBucket {
  count: number;
  windowStart: number;
}

export class RateLimiter {
  private buckets = new Map<string, RateBucket>();
  private readonly maxCalls: number;
  private readonly windowMs: number;

  constructor(maxCalls = 100, windowMs = 60_000) {
    this.maxCalls = maxCalls;
    this.windowMs = windowMs;
  }

  check(key: string): { allowed: boolean; count: number; limit: number; resetsAt: number } {
    const now = Date.now();
    let bucket = this.buckets.get(key);

    if (!bucket || now - bucket.windowStart >= this.windowMs) {
      bucket = { count: 0, windowStart: now };
      this.buckets.set(key, bucket);
    }

    const allowed = bucket.count < this.maxCalls;
    bucket.count++;

    return {
      allowed,
      count: bucket.count,
      limit: this.maxCalls,
      resetsAt: bucket.windowStart + this.windowMs,
    };
  }

  /** Prune expired buckets to prevent memory growth. */
  prune(): void {
    const now = Date.now();
    for (const [key, bucket] of this.buckets) {
      if (now - bucket.windowStart >= this.windowMs) {
        this.buckets.delete(key);
      }
    }
  }
}

// ── Security Engine ──────────────────────────────────────────────────────────

export interface SecurityEngineOptions {
  getRules: (userId?: string) => SiftRule[];
  onAudit: AuditHandler;
  blastRadiusLimit?: number;
  /** Max tool calls per user per minute. 0 = unlimited. */
  rateLimitPerMinute?: number;
  /** Organisation ID — included in audit entries and policy context. */
  orgId?: string;
}

export class SecurityEngine {
  private readonly blastLimiter: BlastRadiusLimiter;
  private readonly rateLimiter: RateLimiter | null;
  private readonly getRules: (userId?: string) => SiftRule[];
  private readonly onAudit: AuditHandler;
  private readonly orgId: string | undefined;
  private pruneTimer: ReturnType<typeof setInterval> | null = null;

  constructor(options: SecurityEngineOptions) {
    this.getRules = options.getRules;
    this.onAudit = options.onAudit;
    this.orgId = options.orgId;
    this.blastLimiter = new BlastRadiusLimiter(options.blastRadiusLimit ?? 10);

    const rateLimit = options.rateLimitPerMinute ?? 0;
    this.rateLimiter = rateLimit > 0 ? new RateLimiter(rateLimit, 60_000) : null;

    // Prune rate limiter buckets every 5 minutes
    if (this.rateLimiter) {
      this.pruneTimer = setInterval(() => this.rateLimiter!.prune(), 5 * 60_000);
      this.pruneTimer.unref();
    }
  }

  /**
   * Evaluate a tool call against all security checks.
   * Returns a verdict BEFORE the tool is executed.
   */
  evaluateInput(call: GenericToolCall): SecurityVerdict {
    const id = randomUUID();
    const rules = this.getRules(call.userId);

    // 1. Rate limiting
    if (this.rateLimiter) {
      const rateCheck = this.rateLimiter.check(this.scopeKey(call, "rate"));
      if (!rateCheck.allowed) {
        return {
          id,
          action: "block",
          triggeredRules: ["rate-limit"],
          piiDetected: false,
          injectionDetected: false,
          blockReason: `Rate limit exceeded (${rateCheck.count}/${rateCheck.limit} calls/min)`,
        };
      }
    }

    return this.evaluatePolicyAndDetectors(call, rules, id, true);
  }

  /**
   * Evaluate policy, PII, and injection checks without mutating stateful limiters.
   * Useful for admin "what would happen?" workflows before a policy is deployed.
   */
  simulateInput(call: GenericToolCall): SecuritySimulationResult {
    const verdict = this.evaluatePolicyAndDetectors(call, this.getRules(call.userId), randomUUID(), false);
    return {
      verdict,
      skippedChecks: ["rate-limit", "blast-radius-limit"],
    };
  }

  private evaluatePolicyAndDetectors(
    call: GenericToolCall,
    rules: SiftRule[],
    id: string,
    includeStatefulChecks: boolean
  ): SecurityVerdict {
    const triggeredRules: string[] = [];
    const ruleResult = evaluateRules(rules, call.tool, call.input);
    triggeredRules.push(...ruleResult.triggeredRules);

    if (ruleResult.action === "block") {
      return {
        id,
        action: "block",
        triggeredRules,
        piiDetected: containsPii(call.input),
        injectionDetected: detectInjection(call.input).detected,
        blockReason: `Blocked by rule: ${triggeredRules.join(", ")}`,
      };
    }

    if (includeStatefulChecks) {
      const blastBlock = this.checkBlastRadius(call, id, triggeredRules);
      if (blastBlock) return blastBlock;
    }

    // 3. PII + injection detection on input
    const piiDetected = containsPii(call.input);
    const injectionDetected = detectInjection(call.input).detected;

    // 4. If action=redact and PII found, sanitize input
    let sanitizedInput: Record<string, unknown> | undefined;
    if (ruleResult.action === "redact" && piiDetected) {
      sanitizedInput = redactPiiDeep(call.input) as Record<string, unknown>;
    }

    return {
      id,
      action: ruleResult.action,
      triggeredRules,
      piiDetected,
      injectionDetected,
      sanitizedInput,
    };
  }

  private checkBlastRadius(
    call: GenericToolCall,
    id: string,
    triggeredRules: string[]
  ): SecurityVerdict | null {
    const blastCheck = this.blastLimiter.check(call.tool, this.scopeKey(call, "blast"));
    if (!blastCheck.allowed) {
      return {
        id,
        action: "block",
        triggeredRules: [...triggeredRules, "blast-radius-limit"],
        piiDetected: containsPii(call.input),
        injectionDetected: detectInjection(call.input).detected,
        blockReason: `Blast radius limit reached (${blastCheck.count}/${blastCheck.limit} destructive operations)`,
      };
    }
    return null;
  }

  /**
   * Inspect tool output after execution.
   * Detects PII and injection in the result and optionally redacts.
   */
  inspectOutput(output: unknown, verdict: SecurityVerdict): OutputInspection {
    const piiDetected = containsPii(output);
    const injectionDetected = detectInjection(output).detected;

    let sanitizedOutput: unknown | undefined;
    if (verdict.action === "redact" && piiDetected) {
      sanitizedOutput = redactPiiDeep(output);
    }

    return { piiDetected, injectionDetected, sanitizedOutput };
  }

  /**
   * Write a complete audit entry for a tool call.
   */
  async audit(
    call: GenericToolCall,
    verdict: SecurityVerdict,
    output: unknown,
    outputInspection: OutputInspection,
    durationMs: number
  ): Promise<void> {
    const entry: AuditEntry = {
      id: verdict.id,
      timestamp: new Date().toISOString(),
      tool: call.tool,
      input: call.input,
      output,
      action: verdict.action,
      triggeredRules: verdict.triggeredRules,
      durationMs,
      piiDetected: verdict.piiDetected || outputInspection.piiDetected,
      injectionDetected: verdict.injectionDetected || outputInspection.injectionDetected,
      userId: call.userId,
      orgId: call.orgId ?? this.orgId,
      sessionId: call.sessionId,
      clientName: call.clientName,
      sequenceNumber: call.sequenceNumber,
    };

    try {
      await this.onAudit(entry);
    } catch (err) {
      process.stderr.write(`[Sift] Audit write failed: ${String(err)}\n`);
    }
  }

  private scopeKey(call: GenericToolCall, kind: "rate" | "blast"): string {
    const org = call.orgId ?? this.orgId;
    const user = call.userId;
    const session = call.sessionId;

    if (kind === "blast" && org && user && session) return `org:${org}:user:${user}:session:${session}`;
    if (org && user) return `org:${org}:user:${user}`;
    if (user) return `user:${user}`;
    if (session) return `session:${session}`;
    if (call.clientName) return `client:${call.clientName}`;
    return "anonymous";
  }
}
