export interface RuleCondition {
  tools?: string[];
  toolPattern?: string;
  pathIncludes?: string[];
  pathOutside?: string;
  inputContains?: Record<string, string>;
  sqlMutation?: boolean;
  sqlDdl?: boolean;
}

function readPath(input: unknown): string {
  if (!input || typeof input !== "object") return "";
  const candidate = (input as Record<string, unknown>)["path"];
  return typeof candidate === "string" ? candidate : "";
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

  const path = readPath(input);
  if (condition.pathIncludes?.length && !condition.pathIncludes.some((needle) => path.includes(needle))) {
    return false;
  }
  if (condition.pathOutside && (!path || path.startsWith(condition.pathOutside))) {
    return false;
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
