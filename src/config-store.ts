import { createClient } from "@supabase/supabase-js";
import { type SiftRule } from "./rules/index.js";
import { resolveTemplates } from "./templates.js";
import {
  writeSignedPolicyCache,
  type PolicyCache as SignedPolicyCachePayload,
} from "./policy-cache.js";
import { buildSupabaseClientOptions } from "./supabase-auth.js";

export type PolicyCache = SignedPolicyCachePayload;

// ── Data model ────────────────────────────────────────────────────────────────

/**
 * A single upstream MCP server that Sift should proxy.
 * Either `command` (stdio) or `url` (HTTP/SSE) must be provided.
 */
export interface UpstreamServer {
  /** Human-readable key — used as a prefix when tool names collide across servers. */
  name: string;
  /** Stdio command array, e.g. ["npx", "-y", "@modelcontextprotocol/server-filesystem", "~/Documents"] */
  command?: string[];
  /** HTTP/SSE URL — mutually exclusive with command. */
  url?: string;
  /** Optional HTTP headers for upstream Streamable HTTP/SSE MCP servers. */
  headers?: Record<string, string>;
  /** Optional per-server environment variable overrides injected into the child process. */
  env?: Record<string, string>;
}

export interface PolicySet {
  policies: string[];
  rules: SiftRule[];
}

export interface GroupConfig {
  id: string;
  name: string;
  description?: string;
  policies: string[];
  rules: SiftRule[];
}

/**
 * Full Sift configuration.
 * Also accepts the legacy flat `policies` / `rules` keys from v1 configs.
 */
/**
 * Controls which users are permitted to use tools through Sift.
 * When `enforced` is true, only users whose email appears in `emails`
 * can execute tool calls — everyone else is blocked.
 */
export interface AllowedUsersConfig {
  /** Whether the restriction is active. */
  enforced: boolean;
  /** Allowed email addresses (case-insensitive match). */
  emails: string[];
}

export interface SiftConfig {
  /**
   * Multi-upstream list. When present and non-empty, Sift acts as a global
   * interceptor — it aggregates tools from all listed servers and presents them
   * as a single MCP surface to the LLM client.
   */
  upstreams?: UpstreamServer[];
  /**
   * @deprecated Single upstream command string. Use `upstreams` instead.
   * Still supported for backwards compatibility.
   */
  upstream?: string;
  /** Default policy — applies to any user with no group assignment. */
  defaultPolicy?: PolicySet;
  /** Named groups that can be assigned to users. */
  groups?: Record<string, GroupConfig>;
  /** userId → groupId mapping. */
  userGroups?: Record<string, string>;
  /** Allowed-users access control — restricts which users can use tools. */
  allowedUsers?: AllowedUsersConfig;
  /** @deprecated Use defaultPolicy.policies instead. */
  policies?: string[];
  /** @deprecated Use defaultPolicy.rules instead. */
  rules?: SiftRule[];
}

// ── Store ─────────────────────────────────────────────────────────────────────

export class ConfigStore {
  private config: SiftConfig;

  constructor(initial: SiftConfig) {
    this.config = initial;
  }

  get(): SiftConfig {
    return this.config;
  }

  update(next: SiftConfig): void {
    this.config = next;
    process.stderr.write("[Sift] Config hot-reloaded — new rules take effect for incoming sessions.\n");
  }

  startSupabaseSync(
    supabaseUrl: string,
    supabaseKey: string,
    intervalMs = 30000,
    orgId?: string,
    cacheSigningSecret?: string
  ): void {
    const supabaseOptions = buildSupabaseClientOptions();
    const client = supabaseOptions
      ? createClient(supabaseUrl, supabaseKey, supabaseOptions)
      : createClient(supabaseUrl, supabaseKey);

    const sync = async (): Promise<void> => {
      try {
        let groupsQuery = client.from("sift_groups").select("*");
        if (orgId) groupsQuery = groupsQuery.eq("org_id", orgId);

        let userGroupsQuery = client.from("sift_user_groups").select("user_id, group_id");
        if (orgId) userGroupsQuery = userGroupsQuery.eq("org_id", orgId);

        // Match either this org's rows OR global null-org rows (written by the
        // dashboard before org scoping is fully enforced). When both exist, the
        // org-specific row takes precedence because find() returns the last match
        // and org-specific rows will appear after null-org rows in result order.
        const configQuery = orgId
          ? client.from("sift_config").select("key, value").or(`org_id.eq.${orgId},org_id.is.null`)
          : client.from("sift_config").select("key, value");

        const [groupsRes, userGroupsRes, configRes] = await Promise.all([
          groupsQuery,
          userGroupsQuery,
          configQuery,
        ]);

        // If ANY query fails, abort the entire sync to avoid overwriting
        // config with partial data. The next sync cycle will retry.
        if (groupsRes.error) throw groupsRes.error;
        if (userGroupsRes.error) throw userGroupsRes.error;
        if (configRes.error) throw configRes.error;

        const groups: Record<string, GroupConfig> = {};
        for (const row of groupsRes.data ?? []) {
          groups[row.id as string] = {
            id: row.id as string,
            name: row.name as string,
            description: row.description as string | undefined,
            policies: (row.policies as string[]) ?? [],
            rules: (row.rules as SiftRule[]) ?? [],
          };
        }

        const userGroups: Record<string, string> = {};
        for (const row of userGroupsRes.data ?? []) {
          userGroups[row.user_id as string] = row.group_id as string;
        }

        // Read default policy and allowed users from sift_config
        let defaultPolicy = this.config.defaultPolicy;
        let allowedUsers = this.config.allowedUsers;
        const dpRow = (configRes.data ?? []).find((r) => r.key === "defaultPolicy");
        if (dpRow) defaultPolicy = dpRow.value as PolicySet;

        const auRow = (configRes.data ?? []).find((r) => r.key === "allowedUsers");
        if (auRow) allowedUsers = auRow.value as AllowedUsersConfig;

        this.config = { ...this.config, groups, userGroups, defaultPolicy, allowedUsers };
        const dpPolicies = defaultPolicy?.policies ?? [];
        const dpRules = defaultPolicy?.rules ?? [];
        const auEnforced = allowedUsers?.enforced ?? false;
        const auCount = allowedUsers?.emails?.length ?? 0;
        process.stderr.write(
          `[Sift] Synced ${Object.keys(groups).length} groups, ${Object.keys(userGroups).length} user assignments from Supabase. Default policy: ${dpPolicies.length} template(s) [${dpPolicies.join(", ")}], ${dpRules.length} custom rule(s). Allowed users: ${auEnforced ? `enforced (${auCount} email${auCount !== 1 ? "s" : ""})` : "off"}.\n`
        );

        // Write policy cache for the Claude Code hook to read
        this.writePolicyCache(cacheSigningSecret);
      } catch (err) {
        process.stderr.write(`[Sift] Supabase sync error: ${String(err)}\n`);
      }
    };

    void sync();
    setInterval(() => { void sync(); }, intervalMs);
  }

  startDashboardSync(
    dashboardUrl: string,
    ingestSecret: string,
    intervalMs = 30000,
    cacheSigningSecret?: string
  ): void {
    const baseUrl = dashboardUrl.replace(/\/$/, "");

    const sync = async (): Promise<void> => {
      try {
        const res = await fetch(`${baseUrl}/api/policy/sync`, {
          headers: { Authorization: `Bearer ${ingestSecret}` },
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);

        const payload = await res.json() as {
          config?: Array<{ key: string; value: unknown }>;
          groups?: GroupConfig[];
          userGroups?: Array<{ user_id: string; group_id: string }>;
        };

        const groups: Record<string, GroupConfig> = {};
        for (const row of payload.groups ?? []) {
          groups[row.id] = {
            id: row.id,
            name: row.name,
            description: row.description,
            policies: row.policies ?? [],
            rules: row.rules ?? [],
          };
        }

        const userGroups: Record<string, string> = {};
        for (const row of payload.userGroups ?? []) {
          userGroups[row.user_id] = row.group_id;
        }

        let defaultPolicy = this.config.defaultPolicy;
        let allowedUsers = this.config.allowedUsers;
        const dpRow = (payload.config ?? []).find((r) => r.key === "defaultPolicy");
        if (dpRow) defaultPolicy = dpRow.value as PolicySet;

        const auRow = (payload.config ?? []).find((r) => r.key === "allowedUsers");
        if (auRow) allowedUsers = auRow.value as AllowedUsersConfig;

        this.config = { ...this.config, groups, userGroups, defaultPolicy, allowedUsers };
        process.stderr.write(
          `[Sift] Synced ${Object.keys(groups).length} groups, ${Object.keys(userGroups).length} user assignments from dashboard backend.\n`
        );
        this.writePolicyCache(cacheSigningSecret);
      } catch (err) {
        process.stderr.write(`[Sift] Dashboard policy sync error: ${String(err)}\n`);
      }
    };

    void sync();
    setInterval(() => { void sync(); }, intervalMs);
  }

  /**
   * Write a policy-cache.json file that the Claude Code hook reads.
   * This keeps hook policy evaluation in sync with Supabase without
   * the hook needing its own Supabase connection.
   */
  private writePolicyCache(cacheSigningSecret?: string): void {
    if (!cacheSigningSecret) {
      process.stderr.write("[Sift] Policy cache signing secret unavailable — skipping policy-cache write.\n");
      return;
    }

    try {
      const cache: PolicyCache = {
        syncedAt: new Date().toISOString(),
        defaultPolicy: this.config.defaultPolicy,
        groups: this.config.groups,
        userGroups: this.config.userGroups,
        allowedUsers: this.config.allowedUsers,
      };
      writeSignedPolicyCache(cache, cacheSigningSecret);
    } catch {
      // Non-fatal — hook will fall back to local-config.json
    }
  }

  /**
   * Check if a user (by email) is permitted to use tools.
   * Returns `true` when:
   *   - Allowed-users enforcement is disabled (default)
   *   - The user's email is in the allowed list (case-insensitive)
   * Returns `false` when enforcement is on and the email is not in the list
   * (or no email is available).
   */
  isUserAllowed(email: string | undefined): boolean {
    const { allowedUsers } = this.config;
    if (!allowedUsers?.enforced) return true;            // not enforced → allow all
    if (!email) return false;                            // enforced but no email → deny
    const lower = email.toLowerCase();
    return (allowedUsers.emails ?? []).some((e) => e.toLowerCase() === lower);
  }

  /**
   * Resolve the effective SiftRule[] for a given userId.
   *
   * Resolution order:
   *   1. User has an explicit group → use that group's policies + rules
   *   2. defaultPolicy is set → use it
   *   3. Legacy flat policies/rules → use them
   *   4. No config → allow all (empty rules)
   */
  resolveRules(userId: string | undefined): SiftRule[] {
    const { defaultPolicy, groups, userGroups, policies, rules } = this.config;

    // 1. User-specific group
    if (userId && userGroups?.[userId]) {
      const groupId = userGroups[userId]!;
      const group = groups?.[groupId];
      if (group) {
        return [
          ...resolveTemplates(group.policies ?? []),
          ...(group.rules ?? []),
        ];
      }
    }

    // 2. Default policy
    if (defaultPolicy) {
      return [
        ...resolveTemplates(defaultPolicy.policies ?? []),
        ...(defaultPolicy.rules ?? []),
      ];
    }

    // 3. Legacy flat format
    return [
      ...resolveTemplates(policies ?? []),
      ...(rules ?? []),
    ];
  }
}
