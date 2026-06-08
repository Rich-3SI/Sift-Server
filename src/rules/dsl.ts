import { isAbsolute, relative, resolve } from "node:path";

export interface RuleCondition {
  tools?: string[];
  toolPattern?: string;
  pathIncludes?: string[];
  pathOutside?: string;
  inputContains?: Record<string, string>;
  sqlMutation?: boolean;
  sqlDdl?: boolean;
}

const PATH_KEYS = ["path", "file_path", "source", "destination", "directory", "dir", "cwd"];

function readPaths(input: unknown): string[] {
  if (!input || typeof input !== "object") return [];
  const record = input as Record<string, unknown>;
  const paths: string[] = [];

  for (const key of PATH_KEYS) {
    const candidate = record[key];
    if (typeof candidate === "string") paths.push(candidate);
  }

  const pathList = record["paths"];
  if (Array.isArray(pathList)) {
    for (const candidate of pathList) {
      if (typeof candidate === "string") paths.push(candidate);
    }
  }

  return paths;
}

function isPathInside(target: string, base: string): boolean {
  const resolvedBase = normalizePathForPolicy(resolve(base));
  const resolvedTarget = normalizePathForPolicy(isAbsolute(target)
    ? resolve(target)
    : resolve(resolvedBase, target));
  const relationship = relative(resolvedBase, resolvedTarget);
  return relationship === "" || (!relationship.startsWith("..") && !isAbsolute(relationship));
}

function normalizePathForPolicy(path: string): string {
  return path.replace(/^\/private\/(tmp|var|etc)(?=\/|$)/, "/$1");
}

function readSql(input: unknown): string {
  if (!input || typeof input !== "object") return "";
  const record = input as Record<string, unknown>;
  for (const key of ["query", "sql", "statement", "command"]) {
    const value = record[key];
    if (typeof value === "string") return value;
  }
  return "";
}

function readString(input: unknown, key: string): string {
  if (!input || typeof input !== "object") return "";
  const value = (input as Record<string, unknown>)[key];
  return typeof value === "string" ? value : "";
}

export function evaluateRuleCondition(
  condition: RuleCondition,
  toolName: string,
  input: unknown
): boolean {
  if (condition.tools && !condition.tools.includes(toolName)) return false;
  if (condition.toolPattern && !new RegExp(condition.toolPattern, "i").test(toolName)) return false;

  const paths = readPaths(input);
  if (condition.pathIncludes?.length && !paths.some((path) => condition.pathIncludes!.some((needle) => path.includes(needle)))) {
    return false;
  }
  if (condition.pathOutside) {
    if (paths.length === 0) return true;
    if (!paths.some((path) => !isPathInside(path, condition.pathOutside!))) {
      return false;
    }
  }

  if (condition.inputContains) {
    for (const [key, expected] of Object.entries(condition.inputContains)) {
      if (!readString(input, key).includes(expected)) return false;
    }
  }

  const sql = readSql(input);
  if (condition.sqlMutation && !/\b(INSERT|UPDATE|DELETE|MERGE|UPSERT)\b/i.test(sql)) {
    return false;
  }
  if (condition.sqlDdl && !/\b(CREATE|ALTER|DROP|TRUNCATE)\b/i.test(sql)) {
    return false;
  }

  return true;
}
