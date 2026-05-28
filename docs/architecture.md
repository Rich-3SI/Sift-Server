# Architecture

Sift has two deployment shapes:

- **Sift Server:** an HTTP MCP gateway for teams. This is the main open-source server product.
- **Sift CLI proxy:** a local stdio wrapper for one upstream MCP server.

## Sift Server Data Flow

```text
MCP client
  |
  | POST /mcp with bearer auth
  v
Sift Server
  |
  | authenticate tenant
  | bind MCP session to tenant
  | list and scan MCP metadata
  | evaluate tool-call policy
  | inspect output
  | write audit
  v
Upstream MCP server(s)
```

## Core Components

| Component | Path | Role |
|---|---|---|
| Sift Server | `sift-server/src/server.ts` | HTTP MCP transport, sessions, auth enforcement, metadata scanning, tool-call handling |
| Auth adapter | `sift-server/src/auth.ts` | API key and JWT validation |
| Config loader | `sift-server/src/config.ts` | Server config parsing and validation |
| Security engine | `src/engine.ts` | Policy evaluation, PII detection, injection detection, rate limiting, blast limiting |
| Rule engine | `src/rules/` | Built-in detectors, condition DSL, sandboxed custom predicates |
| Templates | `src/templates.ts` | Built-in security policies |
| Upstream pool | `src/upstream-pool.ts` | MCP upstream connections and tool-name routing |
| Audit | `src/audit.ts` | Console, SQLite, Supabase, JSONL, and webhook audit handlers |
| Metadata scanner | `src/metadata-scan.ts` | Scans tools, resources, prompts, and returned metadata for risky content |
| Admin API | `sift-server/src/admin.ts` | Reload, session disconnect, and policy simulation |

## Multi-Upstream Routing

Sift Server can connect to multiple upstream MCP servers and expose them as one MCP surface. If two upstreams export the same tool name, Sift prefixes the exposed names as:

```text
<upstream-name>__<tool-name>
```

The routing table maps exposed names back to the original upstream tool.

## Policy Evaluation

Policies are first-match-wins:

1. Resolve effective rules for the user.
2. Apply rate limiting.
3. Evaluate custom rules and templates.
4. Apply blast-radius limiting for destructive tools.
5. Detect PII and prompt-injection patterns.
6. Optionally redact inputs or outputs.
7. Audit the decision.

Admin simulation uses the same policy and detector path, but skips stateful rate and blast counters so dry-runs do not affect real traffic.

## Audit Path

Audit is non-blocking at the handler layer. A failed webhook or remote backend should not prevent a tool call from completing. Sift always keeps a local SQLite fallback when configured with `SIFT_DB_PATH` or the default local path.
