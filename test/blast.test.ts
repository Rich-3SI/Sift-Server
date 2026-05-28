import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { BlastRadiusLimiter, DESTRUCTIVE_TOOLS } from "../src/rules/blast.js";

describe("BlastRadiusLimiter", () => {
  it("allows non-destructive tools without counting", () => {
    const limiter = new BlastRadiusLimiter(3);
    const result = limiter.check("read_file");
    assert.equal(result.allowed, true);
    assert.equal(result.count, 0);
  });

  it("counts destructive tool calls", () => {
    const limiter = new BlastRadiusLimiter(3);
    const r1 = limiter.check("delete_file");
    assert.equal(r1.allowed, true);
    assert.equal(r1.count, 1);

    const r2 = limiter.check("delete_file");
    assert.equal(r2.allowed, true);
    assert.equal(r2.count, 2);
  });

  it("blocks after limit is reached", () => {
    const limiter = new BlastRadiusLimiter(2);
    limiter.check("delete_file"); // 1
    limiter.check("delete_file"); // 2

    const r3 = limiter.check("delete_file"); // 3 → blocked
    assert.equal(r3.allowed, false);
    assert.equal(r3.count, 2);
    assert.equal(r3.limit, 2);
  });

  it("resets count", () => {
    const limiter = new BlastRadiusLimiter(2);
    limiter.check("delete_file");
    limiter.check("delete_file");
    limiter.reset();

    const result = limiter.check("delete_file");
    assert.equal(result.allowed, true);
    assert.equal(result.count, 1);
  });

  it("is case insensitive for tool names", () => {
    const limiter = new BlastRadiusLimiter(5);
    assert.equal(limiter.isDestructive("DELETE_FILE"), true);
    assert.equal(limiter.isDestructive("Delete_File"), true);
  });

  it("recognizes all destructive tools", () => {
    const expected = [
      "delete_file", "remove_file", "drop_table", "delete_row",
      "truncate", "rm", "unlink", "purge", "wipe",
      "delete_database", "drop_collection", "clear_table", "destroy",
    ];
    for (const tool of expected) {
      assert.ok(DESTRUCTIVE_TOOLS.has(tool), `Expected ${tool} to be destructive`);
    }
  });

  it("does not count non-destructive tools", () => {
    const limiter = new BlastRadiusLimiter(1);
    limiter.check("read_file");
    limiter.check("write_file");
    limiter.check("list_directory");
    assert.equal(limiter.getCount(), 0);
  });

  it("tracks destructive calls independently per scope", () => {
    const limiter = new BlastRadiusLimiter(1);

    const a1 = limiter.check("delete_file", "user:a");
    const a2 = limiter.check("delete_file", "user:a");
    const b1 = limiter.check("delete_file", "user:b");

    assert.equal(a1.allowed, true);
    assert.equal(a2.allowed, false);
    assert.equal(b1.allowed, true);
    assert.equal(limiter.getCount("user:a"), 1);
    assert.equal(limiter.getCount("user:b"), 1);
  });
});
