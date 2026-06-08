import { describe, it } from "node:test";
import assert from "node:assert/strict";
import type { IncomingMessage } from "node:http";
import { createHmac } from "node:crypto";
import { buildKeyIndex, extractBearerToken, validateApiKey, validateJwtToken } from "../src/auth.js";

function mockReq(headers: Record<string, string | string[]> = {}): IncomingMessage {
  return { headers } as unknown as IncomingMessage;
}

describe("buildKeyIndex", () => {
  it("indexes keys to tenant contexts", () => {
    const index = buildKeyIndex([
      { key: "sk-1", userId: "alice", orgId: "org-1", email: "alice@example.com" },
      { key: "sk-2", userId: "bob", orgId: "org-1" },
    ]);
    assert.equal(index.size, 2);
    assert.equal(index.get("sk-1")?.userId, "alice");
    assert.equal(index.get("sk-2")?.email, undefined);
  });

  it("does not index revoked or expired keys", () => {
    const index = buildKeyIndex([
      { key: "sk-active", userId: "alice", orgId: "org-1", expiresAt: "2999-01-01T00:00:00.000Z" },
      { key: "sk-revoked", userId: "bob", orgId: "org-1", revoked: true },
      { key: "sk-expired", userId: "carol", orgId: "org-1", expiresAt: "2000-01-01T00:00:00.000Z" },
    ]);

    assert.equal(index.has("sk-active"), true);
    assert.equal(index.has("sk-revoked"), false);
    assert.equal(index.has("sk-expired"), false);
  });
});

describe("extractBearerToken", () => {
  it("returns the token when a valid Bearer header is present", () => {
    const req = mockReq({ authorization: "Bearer sk-test-123" });
    assert.equal(extractBearerToken(req), "sk-test-123");
  });

  it("returns undefined when no authorization header is present", () => {
    assert.equal(extractBearerToken(mockReq()), undefined);
  });

  it("returns undefined when the scheme is not Bearer", () => {
    const req = mockReq({ authorization: "Basic dXNlcjpwYXNz" });
    assert.equal(extractBearerToken(req), undefined);
  });

  it("trims whitespace from tokens", () => {
    const req = mockReq({ authorization: "Bearer    padded-token  " });
    assert.equal(extractBearerToken(req), "padded-token");
  });

  it("returns undefined when the token is empty", () => {
    const req = mockReq({ authorization: "Bearer " });
    assert.equal(extractBearerToken(req), undefined);
  });
});

describe("validateApiKey", () => {
  const index = buildKeyIndex([
    { key: "sk-valid", userId: "alice", orgId: "org-1" },
  ]);

  it("returns the tenant context for a known key", () => {
    const tenant = validateApiKey("sk-valid", index);
    assert.ok(tenant);
    assert.equal(tenant!.userId, "alice");
  });

  it("returns null for an unknown key", () => {
    assert.equal(validateApiKey("sk-unknown", index), null);
  });

  it("returns null for an undefined token", () => {
    assert.equal(validateApiKey(undefined, index), null);
  });

  it("rejects keys that expire after startup", async () => {
    const liveIndex = buildKeyIndex([
      {
        key: "sk-short-lived",
        userId: "alice",
        orgId: "org-1",
        expiresAt: new Date(Date.now() + 20).toISOString(),
      },
    ]);

    assert.equal(validateApiKey("sk-short-lived", liveIndex)?.userId, "alice");
    await new Promise((resolve) => setTimeout(resolve, 40));
    assert.equal(validateApiKey("sk-short-lived", liveIndex), null);
    assert.equal(liveIndex.has("sk-short-lived"), false);
  });
});

describe("validateJwtToken", () => {
  const secret = "test-jwt-secret";

  it("maps a valid HS256 JWT to tenant context", async () => {
    const token = signHs256({
      iss: "https://issuer.example.test",
      aud: "sift-server",
      sub: "user-123",
      org_id: "org-123",
      email: "user@example.test",
      exp: Math.floor(Date.now() / 1000) + 300,
    }, secret);

    const tenant = await validateJwtToken(token, {
      issuer: "https://issuer.example.test",
      audience: "sift-server",
      hmacSecret: secret,
    });

    assert.ok(tenant);
    assert.equal(tenant.userId, "user-123");
    assert.equal(tenant.orgId, "org-123");
    assert.equal(tenant.email, "user@example.test");
  });

  it("rejects JWTs with the wrong audience", async () => {
    const token = signHs256({
      aud: "other-service",
      sub: "user-123",
      org_id: "org-123",
      exp: Math.floor(Date.now() / 1000) + 300,
    }, secret);

    const tenant = await validateJwtToken(token, {
      audience: "sift-server",
      hmacSecret: secret,
    });

    assert.equal(tenant, null);
  });

  it("rejects expired JWTs", async () => {
    const token = signHs256({
      iss: "https://issuer.example.test",
      aud: "sift-server",
      sub: "user-123",
      org_id: "org-123",
      exp: Math.floor(Date.now() / 1000) - 120,
    }, secret);

    const tenant = await validateJwtToken(token, {
      issuer: "https://issuer.example.test",
      audience: "sift-server",
      hmacSecret: secret,
      clockToleranceSeconds: 0,
    });

    assert.equal(tenant, null);
  });

  it("rejects JWTs without exp by default", async () => {
    const token = signHs256({
      iss: "https://issuer.example.test",
      aud: "sift-server",
      sub: "user-123",
      org_id: "org-123",
    }, secret);

    const tenant = await validateJwtToken(token, {
      issuer: "https://issuer.example.test",
      audience: "sift-server",
      hmacSecret: secret,
    });

    assert.equal(tenant, null);
  });

  it("rejects JWTs with malformed exp claims", async () => {
    const token = signHs256({
      iss: "https://issuer.example.test",
      aud: "sift-server",
      sub: "user-123",
      org_id: "org-123",
      exp: "2999-01-01T00:00:00.000Z",
    }, secret);

    const tenant = await validateJwtToken(token, {
      issuer: "https://issuer.example.test",
      audience: "sift-server",
      hmacSecret: secret,
      allowMissingExpiration: true,
    });

    assert.equal(tenant, null);
  });


  it("rejects JWT validation configs without expected issuer or audience by default", async () => {
    const token = signHs256({
      iss: "https://issuer.example.test",
      aud: "sift-server",
      sub: "user-123",
      org_id: "org-123",
      exp: Math.floor(Date.now() / 1000) + 300,
    }, secret);

    assert.equal(await validateJwtToken(token, { hmacSecret: secret, audience: "sift-server" }), null);
    assert.equal(await validateJwtToken(token, { hmacSecret: secret, issuer: "https://issuer.example.test" }), null);
  });

  it("allows explicit local JWT overrides for missing exp, issuer, and audience", async () => {
    const token = signHs256({
      sub: "user-123",
      org_id: "org-123",
    }, secret);

    const tenant = await validateJwtToken(token, {
      hmacSecret: secret,
      allowMissingExpiration: true,
      allowMissingIssuer: true,
      allowMissingAudience: true,
    });

    assert.equal(tenant?.userId, "user-123");
  });
});

function signHs256(payload: Record<string, unknown>, secret: string): string {
  const header = { alg: "HS256", typ: "JWT" };
  const signingInput = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(payload))}`;
  const signature = createHmac("sha256", secret).update(signingInput).digest("base64url");
  return `${signingInput}.${signature}`;
}

function base64url(value: string): string {
  return Buffer.from(value).toString("base64url");
}
