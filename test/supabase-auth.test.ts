import assert from "node:assert/strict";
import { afterEach, test } from "node:test";
import {
  buildSupabaseClientOptions,
  getSupabaseAuthorizationHeader,
} from "../src/supabase-auth.js";

const ORIGINAL_ENV = {
  SIFT_SUPABASE_ACCESS_TOKEN: process.env["SIFT_SUPABASE_ACCESS_TOKEN"],
  SUPABASE_SERVICE_ROLE_KEY: process.env["SUPABASE_SERVICE_ROLE_KEY"],
};

afterEach(() => {
  if (ORIGINAL_ENV.SIFT_SUPABASE_ACCESS_TOKEN === undefined) {
    delete process.env["SIFT_SUPABASE_ACCESS_TOKEN"];
  } else {
    process.env["SIFT_SUPABASE_ACCESS_TOKEN"] = ORIGINAL_ENV.SIFT_SUPABASE_ACCESS_TOKEN;
  }
  if (ORIGINAL_ENV.SUPABASE_SERVICE_ROLE_KEY === undefined) {
    delete process.env["SUPABASE_SERVICE_ROLE_KEY"];
  } else {
    process.env["SUPABASE_SERVICE_ROLE_KEY"] = ORIGINAL_ENV.SUPABASE_SERVICE_ROLE_KEY;
  }
});

test("Supabase endpoint auth uses the signed-in user access token", () => {
  delete process.env["SUPABASE_SERVICE_ROLE_KEY"];
  process.env["SIFT_SUPABASE_ACCESS_TOKEN"] = "user-token";

  assert.equal(getSupabaseAuthorizationHeader(), "Bearer user-token");
  assert.deepEqual(buildSupabaseClientOptions(), {
    auth: { autoRefreshToken: false, persistSession: false },
    global: { headers: { Authorization: "Bearer user-token" } },
  });
});

test("Supabase endpoint auth prefers service role when explicitly configured", () => {
  process.env["SIFT_SUPABASE_ACCESS_TOKEN"] = "user-token";
  process.env["SUPABASE_SERVICE_ROLE_KEY"] = "service-token";

  assert.equal(getSupabaseAuthorizationHeader(), "Bearer service-token");
});

test("Supabase endpoint auth returns no client options when no auth token exists", () => {
  delete process.env["SIFT_SUPABASE_ACCESS_TOKEN"];
  delete process.env["SUPABASE_SERVICE_ROLE_KEY"];

  assert.equal(getSupabaseAuthorizationHeader(), null);
  assert.equal(buildSupabaseClientOptions(), undefined);
});
