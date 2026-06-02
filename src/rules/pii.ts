export const PII_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
  {
    name: "SSN",
    pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
  },
  {
    name: "SSN_NODASH",
    pattern: /\b\d{9}\b/g,
  },
  {
    name: "CARD",
    pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b/g,
  },
  {
    name: "EMAIL",
    pattern: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g,
  },
  {
    name: "PHONE",
    pattern: /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
  },
  {
    name: "PASSPORT",
    pattern: /\b[A-Z]{1,2}[0-9]{6,9}\b/g,
  },
];

const SENSITIVE_KEY_PATTERN =
  /api[_-]?key|password|passwd|secret|token|bearer|private[_-]?key|access[_-]?key|authorization|credential/i;

const CREDENTIAL_VALUE_PATTERNS: Array<{ name: string; pattern: RegExp; replace: string }> = [
  {
    name: "BEARER",
    pattern: /\b(Bearer\s+)[A-Za-z0-9._~+/=-]+/gi,
    replace: "$1[REDACTED:BEARER]",
  },
  {
    name: "CREDENTIAL",
    pattern: /\b(api[_-]?key|password|passwd|secret|token|access[_-]?key)\b\s*[:=]\s*["']?[^"',\s&}]+/gi,
    replace: "$1=[REDACTED:CREDENTIAL]",
  },
];

export function containsPii(value: unknown): boolean {
  const text = JSON.stringify(value);
  return PII_PATTERNS.some(({ pattern }) => {
    pattern.lastIndex = 0;
    return pattern.test(text);
  });
}

export function redactPii(text: string): string {
  let result = text;
  for (const { name, pattern } of PII_PATTERNS) {
    pattern.lastIndex = 0;
    result = result.replace(pattern, `[REDACTED:${name}]`);
  }
  return result;
}

export function redactCredentials(text: string): string {
  let result = text;
  for (const { pattern, replace } of CREDENTIAL_VALUE_PATTERNS) {
    pattern.lastIndex = 0;
    result = result.replace(pattern, replace);
  }
  return result;
}

/**
 * Recursively traverse an object and redact PII in string values.
 * Unlike JSON.stringify → redactPii → JSON.parse, this preserves
 * object structure and cannot corrupt nested JSON.
 */
export function redactPiiDeep(value: unknown): unknown {
  if (typeof value === "string") {
    return redactPii(value);
  }
  if (Array.isArray(value)) {
    return value.map(redactPiiDeep);
  }
  if (value !== null && typeof value === "object") {
    const result: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      result[k] = redactPiiDeep(v);
    }
    return result;
  }
  return value;
}

/**
 * Redact PII plus credential-shaped fields and inline credential values.
 * Used when a policy returns action=redact.
 */
export function redactSensitiveDeep(value: unknown, key?: string): unknown {
  if (key && SENSITIVE_KEY_PATTERN.test(key)) {
    if (value === null || value === undefined) return value;
    return "[REDACTED:CREDENTIAL]";
  }
  if (typeof value === "string") {
    return redactCredentials(redactPii(value));
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactSensitiveDeep(item));
  }
  if (value !== null && typeof value === "object") {
    const result: Record<string, unknown> = {};
    for (const [childKey, childValue] of Object.entries(value)) {
      result[childKey] = redactSensitiveDeep(childValue, childKey);
    }
    return result;
  }
  return value;
}
