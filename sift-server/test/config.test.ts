import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { loadServerConfig, resolveServerOptions, DEFAULTS } from "../src/config.js";

function withTempConfig(body: unknown): string {
  const dir = mkdtempSync(join(tmpdir(), "sift-server-test-"));
  const path = join(dir, "config.json");
  writeFileSync(path, JSON.stringify(body));
  return path;
}

describe("loadServerConfig", () => {
  it("parses a minimal valid config", () => {
    const path = withTempConfig({
      upstreams: [{ name: "fs", command: ["echo", "stub"] }],
      auth: { mode: "api-key", apiKeys: [{ key: "sk", userId: "u", orgId: "o" }] },
    });
    const cfg = loadServerConfig(path);
    assert.ok(cfg.upstreams);
    assert.equal(cfg.upstreams!.length, 1);
    rmSync(path, { force: true });
  });

  it("rejects configs with no upstreams", () => {
    const path = withTempConfig({ upstreams: [] });
    assert.throws(() => loadServerConfig(path), /at least one upstream/i);
    rmSync(path, { force: true });
  });

  it("rejects upstreams with neither command nor url", () => {
    const path = withTempConfig({
      upstreams: [{ name: "broken" }],
      auth: { mode: "api-key", apiKeys: [{ key: "sk", userId: "u", orgId: "o" }] },
    });
    assert.throws(() => loadServerConfig(path), /command.*url/i);
    rmSync(path, { force: true });
  });

  it("rejects headers on stdio upstreams", () => {
    const path = withTempConfig({
      upstreams: [{ name: "stdio", command: ["echo"], headers: { Authorization: "Bearer secret" } }],
      auth: { mode: "api-key", apiKeys: [{ key: "sk", userId: "u", orgId: "o" }] },
    });
    assert.throws(() => loadServerConfig(path), /headers.*HTTP/i);
    rmSync(path, { force: true });
  });

  it("rejects api-key auth with no keys", () => {
    const path = withTempConfig({
      upstreams: [{ name: "fs", command: ["echo"] }],
      auth: { mode: "api-key", apiKeys: [] },
    });
    assert.throws(() => loadServerConfig(path), /no apiKeys/i);
    rmSync(path, { force: true });
  });

  it("rejects duplicate api keys", () => {
    const path = withTempConfig({
      upstreams: [{ name: "fs", command: ["echo"] }],
      auth: {
        mode: "api-key",
        apiKeys: [
          { key: "dup", userId: "u1", orgId: "o" },
          { key: "dup", userId: "u2", orgId: "o" },
        ],
      },
    });
    assert.throws(() => loadServerConfig(path), /duplicate apiKey/i);
    rmSync(path, { force: true });
  });

  it("rejects invalid api key expiration timestamps", () => {
    const path = withTempConfig({
      upstreams: [{ name: "fs", command: ["echo"] }],
      auth: {
        mode: "api-key",
        apiKeys: [{ key: "sk", userId: "u", orgId: "o", expiresAt: "next tuesday" }],
      },
    });
    assert.throws(() => loadServerConfig(path), /expiresAt/i);
    rmSync(path, { force: true });
  });

  it("accepts auth.mode=none with no api keys", () => {
    const path = withTempConfig({
      upstreams: [{ name: "fs", command: ["echo"] }],
      auth: { mode: "none" },
    });
    const cfg = loadServerConfig(path);
    assert.equal(cfg.auth?.mode, "none");
    rmSync(path, { force: true });
  });

  it("accepts jwt auth with an HMAC secret", () => {
    const path = withTempConfig({
      upstreams: [{ name: "fs", command: ["echo"] }],
      auth: {
        mode: "jwt",
        jwt: {
          issuer: "https://issuer.example.test",
          audience: "sift-server",
          hmacSecret: "dev-secret",
        },
      },
    });
    const cfg = loadServerConfig(path);
    assert.equal(cfg.auth?.mode, "jwt");
    assert.equal(cfg.auth?.jwt?.audience, "sift-server");
    rmSync(path, { force: true });
  });

  it("rejects jwt auth without expected issuer by default", () => {
    const path = withTempConfig({
      upstreams: [{ name: "fs", command: ["echo"] }],
      auth: {
        mode: "jwt",
        jwt: {
          audience: "sift-server",
          hmacSecret: "dev-secret",
        },
      },
    });
    assert.throws(() => loadServerConfig(path), /issuer is required/i);
    rmSync(path, { force: true });
  });

  it("rejects jwt auth without expected audience by default", () => {
    const path = withTempConfig({
      upstreams: [{ name: "fs", command: ["echo"] }],
      auth: {
        mode: "jwt",
        jwt: {
          issuer: "https://issuer.example.test",
          hmacSecret: "dev-secret",
        },
      },
    });
    assert.throws(() => loadServerConfig(path), /audience is required/i);
    rmSync(path, { force: true });
  });

  it("accepts explicit local jwt issuer and audience overrides", () => {
    const path = withTempConfig({
      upstreams: [{ name: "fs", command: ["echo"] }],
      auth: {
        mode: "jwt",
        jwt: {
          hmacSecret: "dev-secret",
          allowMissingIssuer: true,
          allowMissingAudience: true,
          allowMissingExpiration: true,
        },
      },
    });
    const cfg = loadServerConfig(path);
    assert.equal(cfg.auth?.jwt?.allowMissingIssuer, true);
    rmSync(path, { force: true });
  });

  it("rejects jwt auth with no verification material", () => {
    const path = withTempConfig({
      upstreams: [{ name: "fs", command: ["echo"] }],
      auth: { mode: "jwt", jwt: { issuer: "https://issuer.example.test" } },
    });
    assert.throws(() => loadServerConfig(path), /jwksUrl, jwks, or hmacSecret/i);
    rmSync(path, { force: true });
  });

  it("accepts api-key-or-jwt with only api keys for migration configs", () => {
    const path = withTempConfig({
      upstreams: [{ name: "fs", command: ["echo"] }],
      auth: {
        mode: "api-key-or-jwt",
        apiKeys: [{ key: "sk", userId: "u", orgId: "o" }],
      },
    });
    const cfg = loadServerConfig(path);
    assert.equal(cfg.auth?.mode, "api-key-or-jwt");
    rmSync(path, { force: true });
  });

  it("rejects invalid metadata scan actions", () => {
    const path = withTempConfig({
      upstreams: [{ name: "fs", command: ["echo"] }],
      auth: { mode: "none" },
      metadataScan: { action: "drop" },
    });
    assert.throws(() => loadServerConfig(path), /metadataScan\.action/i);
    rmSync(path, { force: true });
  });

  it("rejects invalid audit webhook urls", () => {
    const path = withTempConfig({
      upstreams: [{ name: "fs", command: ["echo"] }],
      auth: { mode: "none" },
      audit: { webhooks: [{ url: "not a url" }] },
    });
    assert.throws(() => loadServerConfig(path), /invalid audit webhook URL/i);
    rmSync(path, { force: true });
  });
});

describe("resolveServerOptions", () => {
  it("applies defaults when fields are missing", () => {
    const opts = resolveServerOptions({
      upstreams: [{ name: "fs", command: ["echo"] }],
    });
    assert.equal(opts.port, DEFAULTS.port);
    assert.equal(opts.host, DEFAULTS.host);
    assert.equal(opts.adminPort, DEFAULTS.adminPort);
    assert.equal(opts.adminHost, DEFAULTS.adminHost);
    assert.equal(opts.maxSessions, DEFAULTS.maxSessions);
    assert.equal(opts.blastRadiusLimit, DEFAULTS.blastRadiusLimit);
    assert.equal(opts.rateLimitPerMinute, DEFAULTS.rateLimitPerMinute);
    assert.equal(opts.metadataScan.enabled, true);
    assert.equal(opts.metadataScan.action, "warn");
  });

  it("respects explicit values over defaults", () => {
    const opts = resolveServerOptions({
      upstreams: [{ name: "fs", command: ["echo"] }],
      server: { port: 9090, host: "127.0.0.1", adminPort: 9091, adminHost: "0.0.0.0" },
      maxSessions: 50,
      sessionTtlMinutes: 5,
      blastRadiusLimit: 3,
      rateLimitPerMinute: 20,
    });
    assert.equal(opts.port, 9090);
    assert.equal(opts.host, "127.0.0.1");
    assert.equal(opts.adminPort, 9091);
    assert.equal(opts.adminHost, "0.0.0.0");
    assert.equal(opts.maxSessions, 50);
    assert.equal(opts.sessionTtlMs, 5 * 60_000);
    assert.equal(opts.blastRadiusLimit, 3);
    assert.equal(opts.rateLimitPerMinute, 20);
  });

  it("resolves audit and metadata scan options", () => {
    const opts = resolveServerOptions({
      upstreams: [{ name: "fs", command: ["echo"] }],
      audit: { jsonlPath: "/tmp/sift-audit.jsonl" },
      metadataScan: { action: "block", includeSchemas: false },
    });
    assert.equal(opts.audit?.jsonlPath, "/tmp/sift-audit.jsonl");
    assert.equal(opts.metadataScan.action, "block");
    assert.equal(opts.metadataScan.includeSchemas, false);
    assert.equal(opts.metadataScan.maxStringLength, DEFAULTS.metadataScan.maxStringLength);
  });
});
