# Security Model

Sift is an MCP security gateway. It gives operators a policy and audit point between AI agents and MCP tools.

## Primary Security Goals

- Authenticate the caller before an MCP session is created.
- Bind every MCP session to the authenticated tenant.
- Reject missing, invalid, or mismatched bearer tokens.
- Enforce policy before an upstream tool executes.
- Inspect tool output before returning it to the client.
- Scan MCP metadata that can influence agent behavior.
- Record every allowed, blocked, and redacted tool call.

## Trust Boundaries

```text
MCP client / agent
  | untrusted tool intent
  v
Sift Server
  | authenticated and policy-checked MCP requests
  v
Upstream MCP servers
  | tool output and metadata
  v
Sift Server
  | inspected result
  v
MCP client / agent
```

Sift treats client intent, upstream metadata, and upstream output as untrusted.

## Authentication

Sift Server supports:

- Static API keys for simple deployments and service accounts.
- JWT bearer tokens for OIDC-style identity providers.
- Mixed `api-key-or-jwt` mode for migrations.

Production deployments should prefer JWT/JWKS or another centrally managed identity source over long-lived static keys.

## Metadata Scanning

MCP servers can return descriptions, prompts, resources, templates, and schemas. These fields can influence how an agent behaves. Sift scans metadata for:

- Prompt-injection patterns.
- PII patterns.

Metadata scan mode can be:

- `warn`: audit findings and still return metadata.
- `block`: hide unsafe listed metadata or reject unsafe returned metadata.

## Policy Enforcement

Policies can:

- Allow a matching call.
- Block a matching call.
- Redact PII from inputs and outputs.

Rules are first-match-wins. Put narrow high-confidence blocks before broad allow or redact rules.

## What Sift Does Not Replace

Sift is not a complete security platform by itself. It does not replace:

- Endpoint security.
- Network controls.
- Secrets management.
- Source-code scanning.
- Container sandboxing for untrusted code.
- Human approval for high-risk business workflows.

For stronger isolation, run upstream MCP servers in containers or another sandbox and use Sift as the policy and audit brain in front of them.

## Deployment Guidance

- Bind admin endpoints to a trusted network.
- Set `SIFT_ADMIN_SECRET`.
- Rotate quickstart or demo credentials before shared use.
- Export audits to your logging system.
- Keep upstream credentials scoped to the minimum required permissions.
- Prefer one Sift Server instance per trust zone.
- Test policies with `/admin/simulate` before broad rollout.
