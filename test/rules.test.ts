import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { evaluateRules, type SiftRule } from "../src/rules/index.js";

describe("evaluateRules", () => {
  const rules: SiftRule[] = [
    {
      id: "block-write",
      description: "Block write_file",
      match: "(toolName) => toolName === 'write_file'",
      action: "block",
    },
    {
      id: "redact-env",
      description: "Redact .env reads",
      match: "(toolName, input) => toolName === 'read_file' && typeof input?.path === 'string' && input.path.includes('.env')",
      action: "redact",
    },
    {
      id: "allow-reads",
      description: "Allow all reads",
      match: "(toolName) => toolName.startsWith('read_')",
      action: "allow",
    },
  ];

  it("blocks matching tool calls", () => {
    const result = evaluateRules(rules, "write_file", { path: "/tmp/test.txt" });
    assert.equal(result.action, "block");
    assert.deepEqual(result.triggeredRules, ["block-write"]);
  });

  it("applies first matching rule (redact before allow)", () => {
    const result = evaluateRules(rules, "read_file", { path: "/home/.env" });
    assert.equal(result.action, "redact");
    assert.deepEqual(result.triggeredRules, ["redact-env"]);
  });

  it("falls through to later rules", () => {
    const result = evaluateRules(rules, "read_file", { path: "/tmp/data.json" });
    assert.equal(result.action, "allow");
    assert.deepEqual(result.triggeredRules, ["allow-reads"]);
  });

  it("defaults to allow when no rules match", () => {
    const result = evaluateRules(rules, "list_directory", {});
    assert.equal(result.action, "allow");
    assert.deepEqual(result.triggeredRules, []);
  });

  it("handles empty rule set", () => {
    const result = evaluateRules([], "write_file", {});
    assert.equal(result.action, "allow");
    assert.deepEqual(result.triggeredRules, []);
  });

  it("handles malformed rule match gracefully", () => {
    const badRules: SiftRule[] = [
      { id: "bad", description: "Broken", match: "this is not valid js", action: "block" },
      { id: "fallback", description: "Fallback", match: "() => true", action: "allow" },
    ];
    const result = evaluateRules(badRules, "anything", {});
    // Bad rule should be skipped, fallback should match
    assert.equal(result.action, "allow");
    assert.deepEqual(result.triggeredRules, ["fallback"]);
  });

  it("passes input correctly to predicate", () => {
    const inputRules: SiftRule[] = [
      {
        id: "block-sql-drop",
        description: "Block DROP TABLE",
        match: "() => false",
        condition: { tools: ["execute_sql"], sqlDdl: true },
        action: "block",
      },
    ];
    const result = evaluateRules(inputRules, "execute_sql", { query: "DROP TABLE users" });
    assert.equal(result.action, "block");

    const safe = evaluateRules(inputRules, "execute_sql", { query: "SELECT * FROM users" });
    assert.equal(safe.action, "allow");
  });

  it("supports condition DSL path boundaries without compiling JavaScript", () => {
    const dslRules: SiftRule[] = [
      {
        id: "block-outside-workspace",
        description: "Block writes outside workspace",
        match: "() => false",
        condition: { tools: ["write_file"], pathOutside: "/Users/alice/project" },
        action: "block",
      },
    ];

    assert.equal(
      evaluateRules(dslRules, "write_file", { path: "/Users/alice/.ssh/config" }).action,
      "block"
    );
    assert.equal(
      evaluateRules(dslRules, "write_file", { path: "/Users/alice/project/README.md" }).action,
      "allow"
    );
  });

  it("skips unsafe custom predicates", () => {
    const unsafeRules: SiftRule[] = [
      {
        id: "unsafe",
        description: "Attempt to reach process",
        match: "() => typeof process !== 'undefined'",
        action: "block",
      },
    ];

    const result = evaluateRules(unsafeRules, "write_file", {});
    assert.equal(result.action, "allow");
    assert.deepEqual(result.triggeredRules, []);
  });
});
