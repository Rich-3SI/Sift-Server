export const INJECTION_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
  { name: "ignore_previous", pattern: /ignore\s+(?:all\s+)?previous\s+instructions/i },
  { name: "you_are_now", pattern: /you\s+are\s+now\s+(?:a|an|the)\s+/i },
  { name: "system_prompt", pattern: /\bsystem\s+prompt\b/i },
  { name: "inst_tag", pattern: /\[INST\]/i },
  { name: "forget_instructions", pattern: /forget\s+(?:your\s+)?instructions/i },
  { name: "new_persona", pattern: /new\s+persona/i },
  { name: "dan_mode", pattern: /DAN\s+mode/i },
  { name: "jailbreak", pattern: /jailbreak/i },
  { name: "override_safety", pattern: /override\s+(?:safety|security|policy|guidelines)/i },
  { name: "act_as", pattern: /act\s+as\s+(?:if\s+you\s+(?:are|were)|a|an)\s+/i },
  { name: "disregard", pattern: /disregard\s+(?:all\s+)?(?:previous|prior|above)\s+/i },
  { name: "prompt_injection", pattern: /\bprompt\s+injection\b/i },
];

export interface InjectionResult {
  detected: boolean;
  matches: string[];
}

export function detectInjection(content: unknown): InjectionResult {
  const text = JSON.stringify(content);
  const matches: string[] = [];

  for (const { name, pattern } of INJECTION_PATTERNS) {
    if (pattern.test(text)) {
      matches.push(name);
    }
  }

  return {
    detected: matches.length > 0,
    matches,
  };
}
