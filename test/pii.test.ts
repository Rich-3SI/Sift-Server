import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { containsPii, redactPii } from "../src/rules/pii.js";

describe("containsPii", () => {
  it("detects SSN with dashes", () => {
    assert.equal(containsPii({ text: "SSN: 123-45-6789" }), true);
  });

  it("detects email addresses", () => {
    assert.equal(containsPii({ email: "user@example.com" }), true);
  });

  it("detects phone numbers", () => {
    assert.equal(containsPii({ phone: "(555) 123-4567" }), true);
    assert.equal(containsPii({ phone: "+1-555-123-4567" }), true);
    assert.equal(containsPii({ phone: "555.123.4567" }), true);
  });

  it("detects credit card numbers", () => {
    // Visa
    assert.equal(containsPii({ card: "4111111111111111" }), true);
    // Mastercard
    assert.equal(containsPii({ card: "5500000000000004" }), true);
    // Amex
    assert.equal(containsPii({ card: "340000000000009" }), true);
  });

  it("returns false for clean data", () => {
    assert.equal(containsPii({ name: "John", age: 30 }), false);
    assert.equal(containsPii({ path: "/tmp/test.txt" }), false);
    assert.equal(containsPii("just a normal string"), false);
  });

  it("handles nested objects", () => {
    assert.equal(containsPii({ deep: { nested: { ssn: "123-45-6789" } } }), true);
  });

  it("handles null and undefined", () => {
    assert.equal(containsPii(null), false);
    assert.equal(containsPii(undefined), false);
  });

  it("handles arrays", () => {
    assert.equal(containsPii(["user@test.com", "hello"]), true);
    assert.equal(containsPii(["hello", "world"]), false);
  });
});

describe("redactPii", () => {
  it("redacts SSN", () => {
    const result = redactPii("My SSN is 123-45-6789");
    assert.equal(result, "My SSN is [REDACTED:SSN]");
    assert.equal(result.includes("123-45-6789"), false);
  });

  it("redacts email", () => {
    const result = redactPii("Contact: user@example.com");
    assert.equal(result.includes("user@example.com"), false);
    assert.ok(result.includes("[REDACTED:EMAIL]"));
  });

  it("redacts phone numbers", () => {
    const result = redactPii("Call me at (555) 123-4567");
    assert.equal(result.includes("(555) 123-4567"), false);
    assert.ok(result.includes("[REDACTED:PHONE]"));
  });

  it("redacts credit cards", () => {
    const result = redactPii("Card: 4111111111111111");
    assert.equal(result.includes("4111111111111111"), false);
    assert.ok(result.includes("[REDACTED:CARD]"));
  });

  it("redacts multiple PII types in same string", () => {
    const input = "SSN: 123-45-6789, email: test@test.com";
    const result = redactPii(input);
    assert.equal(result.includes("123-45-6789"), false);
    assert.equal(result.includes("test@test.com"), false);
  });

  it("leaves clean text untouched", () => {
    const input = "Hello world, this is a test";
    assert.equal(redactPii(input), input);
  });
});
