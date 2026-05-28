import test from "node:test";
import assert from "node:assert/strict";
import {
  signPolicyCache,
  verifySignedPolicyCache,
} from "../src/policy-cache.js";

test("verifySignedPolicyCache accepts a valid signed payload", () => {
  const payload = {
    syncedAt: "2026-04-23T00:00:00.000Z",
    userGroups: { user_123: "group_a" },
    allowedUsers: { enforced: true, emails: ["alice@example.com"] },
  };
  const signature = signPolicyCache(payload, "secret");
  const verified = verifySignedPolicyCache(
    JSON.stringify({ ...payload, signature }),
    "secret"
  );

  assert.equal(verified.ok, true);
  if (verified.ok) {
    assert.equal(verified.cache.signature, signature);
    assert.deepEqual(verified.cache.userGroups, payload.userGroups);
  }
});

test("verifySignedPolicyCache rejects tampered payloads", () => {
  const payload = {
    syncedAt: "2026-04-23T00:00:00.000Z",
    allowedUsers: { enforced: false, emails: [] },
  };
  const signature = signPolicyCache(payload, "secret");
  const verified = verifySignedPolicyCache(
    JSON.stringify({
      ...payload,
      allowedUsers: { enforced: true, emails: ["mallory@example.com"] },
      signature,
    }),
    "secret"
  );

  assert.equal(verified.ok, false);
  if (!verified.ok) {
    assert.equal(verified.reason, "signature mismatch");
  }
});

test("verifySignedPolicyCache rejects unsigned payloads", () => {
  const verified = verifySignedPolicyCache(
    JSON.stringify({ syncedAt: "2026-04-23T00:00:00.000Z" }),
    "secret"
  );

  assert.equal(verified.ok, false);
  if (!verified.ok) {
    assert.equal(verified.reason, "missing signature");
  }
});
