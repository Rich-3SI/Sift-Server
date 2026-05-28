import { type SiftRule } from "./rules/index.js";
import { resolveTemplates } from "./templates.js";

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

/**
 * Full Sift configuration.
 * Also accepts the legacy flat `policies` / `rules` keys from v1 configs.
 */
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
    if (!allowedUsers?.enforced) return true;
    if (!email) return false;
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

    if (defaultPolicy) {
      return [
        ...resolveTemplates(defaultPolicy.policies ?? []),
        ...(defaultPolicy.rules ?? []),
      ];
    }

    return [
      ...resolveTemplates(policies ?? []),
      ...(rules ?? []),
    ];
  }
}
