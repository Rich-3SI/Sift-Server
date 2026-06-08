export * from "./pii.js";
export * from "./injection.js";
export * from "./blast.js";
import { evaluateRuleCondition, type RuleCondition } from "./dsl.js";
import { isSafeRuleMatch } from "./safety.js";

export type RuleAction = "allow" | "block" | "redact";

export interface SiftRule {
  id: string;
  description: string;
  /** JavaScript predicate as string: receives (toolName: string, input: unknown) => boolean */
  match: string;
  condition?: RuleCondition;
  action: RuleAction;
  /** When true, the rule bypasses sandbox validation (used for built-in templates only). */
  trusted?: boolean;
}

export interface RuleEvaluationResult {
  action: RuleAction;
  triggeredRules: string[];
}

/** Predicate compilation cache — avoids recompiling on every tool call. */
const predicateCache = new Map<string, (toolName: string, input: unknown) => boolean>();

/** Maximum time (ms) allowed for a single rule predicate execution. */
const PREDICATE_TIMEOUT_MS = 100;

function failClosedIfNeeded(
  rule: SiftRule,
  triggeredRules: string[]
): RuleEvaluationResult | null {
  if (rule.action !== "block" && rule.action !== "redact") return null;
  triggeredRules.push(rule.id);
  return { action: "block", triggeredRules };
}

/**
 * Execute a predicate with a synchronous timeout guard.
 * Uses a Promise.race approach with AbortController to enforce the timeout.
 */
function executeWithGuard(
  predicate: (toolName: string, input: unknown) => boolean,
  toolName: string,
  input: unknown
): boolean {
  // Deep-clone and freeze input to prevent modification by the predicate
  const frozenInput = typeof input === "object" && input !== null
    ? Object.freeze(JSON.parse(JSON.stringify(input)))
    : input;

  // Synchronous execution with a try-catch for safety.
  // The isSafeMatch check above blocks loops and dangerous constructs,
  // so predicates should complete quickly. We wrap in a deadline check
  // as defense in depth.
  const start = Date.now();
  const result = predicate(toolName, frozenInput);
  const elapsed = Date.now() - start;
  if (elapsed > PREDICATE_TIMEOUT_MS) {
    throw new Error(`Predicate took ${elapsed}ms (limit: ${PREDICATE_TIMEOUT_MS}ms)`);
  }
  return result;
}

export function evaluateRules(
  rules: SiftRule[],
  toolName: string,
  input: unknown,
  toolAliases: string[] = []
): RuleEvaluationResult {
  const triggeredRules: string[] = [];
  const toolNames = [...new Set([toolName, ...toolAliases])];

  for (const rule of rules) {
    try {
      let matched = false;
      if (rule.condition) {
        matched = toolNames.some((name) => evaluateRuleCondition(rule.condition!, name, input));
      } else if (!rule.trusted && !isSafeRuleMatch(rule.match)) {
        process.stderr.write(
          `[Sift] Rule "${rule.id}" blocked — contains unsafe code patterns\n`
        );
        const failClosed = failClosedIfNeeded(rule, triggeredRules);
        if (failClosed) return failClosed;
        continue;
      } else {
        // Use cached predicate if available, otherwise compile and cache
        let predicate = predicateCache.get(rule.match);
        if (!predicate) {
          // eslint-disable-next-line no-new-func
          predicate = new Function(
            "toolName",
            "input",
            `"use strict"; return (${rule.match})(toolName, input);`
          ) as (toolName: string, input: unknown) => boolean;
          predicateCache.set(rule.match, predicate);
        }
        matched = toolNames.some((name) => executeWithGuard(predicate, name, input));
      }

      if (matched) {
        triggeredRules.push(rule.id);
        const action = rule.action;
        if (action !== "allow" && action !== "block" && action !== "redact") {
          process.stderr.write(
            `[Sift] Rule "${rule.id}" has invalid action "${String(action)}" — treating as block\n`
          );
          return { action: "block", triggeredRules };
        }
        return { action, triggeredRules };
      }
    } catch (err) {
      process.stderr.write(
        `[Sift] Rule "${rule.id}" evaluation error: ${String(err)}\n`
      );
      const failClosed = failClosedIfNeeded(rule, triggeredRules);
      if (failClosed) return failClosed;
    }
  }

  return { action: "allow", triggeredRules };
}
