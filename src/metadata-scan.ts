import { containsPii, detectInjection } from "./rules/index.js";

export type MetadataKind =
  | "tool"
  | "resource"
  | "resource-template"
  | "prompt"
  | "prompt-result"
  | "resource-result";

export type MetadataScanAction = "warn" | "block";

export interface MetadataScanOptions {
  enabled?: boolean;
  action?: MetadataScanAction;
  includeSchemas?: boolean;
  maxStringLength?: number;
}

export interface MetadataScanFinding {
  kind: MetadataKind;
  itemName?: string;
  path: string;
  piiDetected: boolean;
  injectionDetected: boolean;
  injectionMatches: string[];
  snippet: string;
}

export interface MetadataScanListResult<T> {
  items: T[];
  findings: MetadataScanFinding[];
  blockedCount: number;
}

const DEFAULT_OPTIONS: Required<MetadataScanOptions> = {
  enabled: true,
  action: "warn",
  includeSchemas: true,
  maxStringLength: 20_000,
};

const SCHEMA_KEYS = new Set(["inputSchema", "outputSchema", "schema"]);

export function scanMetadataItems<T>(
  kind: MetadataKind,
  items: T[],
  options: MetadataScanOptions = {}
): MetadataScanListResult<T> {
  const resolved = resolveOptions(options);
  if (!resolved.enabled) return { items, findings: [], blockedCount: 0 };

  const findings: MetadataScanFinding[] = [];
  const safeItems: T[] = [];
  let blockedCount = 0;

  for (const item of items) {
    const itemFindings = scanMetadataValue(kind, item, options);
    findings.push(...itemFindings);
    if (resolved.action === "block" && itemFindings.length > 0) {
      blockedCount += 1;
    } else {
      safeItems.push(item);
    }
  }

  return { items: safeItems, findings, blockedCount };
}

export function scanMetadataValue(
  kind: MetadataKind,
  value: unknown,
  options: MetadataScanOptions = {}
): MetadataScanFinding[] {
  const resolved = resolveOptions(options);
  if (!resolved.enabled) return [];

  const findings: MetadataScanFinding[] = [];
  const itemName = inferItemName(value);
  visitValue(value, {
    kind,
    itemName,
    path: "$",
    findings,
    options: resolved,
    depth: 0,
  });
  return findings;
}

export function shouldBlockMetadata(
  findings: MetadataScanFinding[],
  options: MetadataScanOptions = {}
): boolean {
  const resolved = resolveOptions(options);
  return resolved.enabled && resolved.action === "block" && findings.length > 0;
}

function resolveOptions(options: MetadataScanOptions): Required<MetadataScanOptions> {
  return { ...DEFAULT_OPTIONS, ...options };
}

function visitValue(
  value: unknown,
  ctx: {
    kind: MetadataKind;
    itemName?: string;
    path: string;
    findings: MetadataScanFinding[];
    options: Required<MetadataScanOptions>;
    depth: number;
  }
): void {
  if (ctx.depth > 12) return;

  if (typeof value === "string") {
    scanString(value, ctx);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => {
      visitValue(item, { ...ctx, path: `${ctx.path}[${index}]`, depth: ctx.depth + 1 });
    });
    return;
  }
  if (value === null || typeof value !== "object") return;

  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    if (!ctx.options.includeSchemas && SCHEMA_KEYS.has(key)) continue;
    visitValue(child, {
      ...ctx,
      path: `${ctx.path}.${key}`,
      depth: ctx.depth + 1,
    });
  }
}

function scanString(
  value: string,
  ctx: {
    kind: MetadataKind;
    itemName?: string;
    path: string;
    findings: MetadataScanFinding[];
    options: Required<MetadataScanOptions>;
  }
): void {
  if (value.length === 0) return;
  const sample = value.length > ctx.options.maxStringLength
    ? value.slice(0, ctx.options.maxStringLength)
    : value;
  const injection = detectInjection(sample);
  const piiDetected = containsPii(sample);
  if (!injection.detected && !piiDetected) return;

  ctx.findings.push({
    kind: ctx.kind,
    itemName: ctx.itemName,
    path: ctx.path,
    piiDetected,
    injectionDetected: injection.detected,
    injectionMatches: injection.matches,
    snippet: sample.slice(0, 240),
  });
}

function inferItemName(value: unknown): string | undefined {
  if (value === null || typeof value !== "object") return undefined;
  const record = value as Record<string, unknown>;
  for (const key of ["name", "uri", "uriTemplate", "title"]) {
    const candidate = record[key];
    if (typeof candidate === "string" && candidate.length > 0) return candidate;
  }
  return undefined;
}
