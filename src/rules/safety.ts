const BLOCKED_GLOBALS = [
  "process", "require", "import", "globalThis", "global",
  "eval", "Function", "fetch", "XMLHttpRequest",
  "setTimeout", "setInterval", "setImmediate",
  "Buffer", "Deno", "Bun",
  "Proxy", "Reflect", "constructor",
  "__proto__", "prototype",
  "Object", "Array",
  "Symbol", "Promise", "RegExp", "Error",
  "Map", "Set", "WeakMap", "WeakSet",
  "Atomics", "SharedArrayBuffer",
  "WebAssembly", "Worker",
];

const BLOCKED_RE = new RegExp(`\\b(${BLOCKED_GLOBALS.join("|")})\\b`);

const ESCAPE_PATTERNS = [
  /\bthis\b/,
  /\[\s*['"`]constructor['"]\s*\]/,
  /\.constructor\b/,
  /\.__proto__\b/,
  /\bimport\s*\(/,
  /\bawait\b/,
  /\byield\b/,
  /while\s*\([^)]*\)\s*\{/,
  /for\s*\([^)]*\)\s*\{/,
  /\bdo\s*\{/,
  /\[\s*['"`]__proto__['"]\s*\]/,
  /\bgetPrototypeOf\b/,
  /\bsetPrototypeOf\b/,
  /\bdefineProperty\b/,
  /\bgetOwnPropertyDescriptor\b/,
  /\bcall\s*\(/,
  /\bapply\s*\(/,
  /\bbind\s*\(/,
  /\bnew\s+/,
  /\bdelete\b/,
  new RegExp(`\\btypeof\\s+(${[
    "process", "require", "global", "globalThis", "eval", "Function",
    "fetch", "Buffer", "Deno", "Bun", "XMLHttpRequest",
  ].join("|")})\\b`),
  /\\\\/,
];

export function isSafeRuleMatch(match: string): boolean {
  if (!/^\s*\([\w\s,?:]*\)\s*=>/.test(match)) return false;
  if (BLOCKED_RE.test(match)) return false;
  for (const pattern of ESCAPE_PATTERNS) {
    if (pattern.test(match)) return false;
  }
  if (match.length > 2000) return false;
  if (match.includes(";")) return false;
  return true;
}
