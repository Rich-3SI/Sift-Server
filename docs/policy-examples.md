# Policy Examples

Sift policies are first-match-wins. Each rule can use either the condition DSL or a JavaScript predicate string.

Prefer built-in templates and condition rules for clarity. Use JavaScript predicates when the rule needs custom logic.

## Block Filesystem Writes

```json
{
  "defaultPolicy": {
    "policies": ["block-filesystem-writes"],
    "rules": []
  }
}
```

## Sandbox Filesystem Access

```json
{
  "defaultPolicy": {
    "policies": ["sandbox-filesystem"],
    "rules": []
  }
}
```

This template blocks file access outside approved sandbox paths.

## Block A Destructive Tool

```json
{
  "id": "block-delete-repo",
  "description": "Never allow repository deletion through MCP",
  "match": "() => false",
  "condition": {
    "tools": ["delete_repo"]
  },
  "action": "block"
}
```

## Redact Credentials

```json
{
  "defaultPolicy": {
    "policies": ["redact-credentials"],
    "rules": []
  }
}
```

## Block Writes Outside A Directory

```json
{
  "id": "block-writes-outside-workspace",
  "description": "Allow write_file only under /workspace",
  "match": "(toolName, input) => toolName === 'write_file' && typeof input?.path === 'string' && !input.path.startsWith('/workspace/')",
  "action": "block"
}
```

## Redact PII For One Tool

```json
{
  "id": "redact-send-email",
  "description": "Redact PII in send_email inputs and outputs",
  "match": "(toolName) => toolName === 'send_email'",
  "action": "redact"
}
```

## Test A Policy Without Executing It

Use the admin simulation endpoint:

```bash
curl -s http://127.0.0.1:18081/admin/simulate \
  -H "Content-Type: application/json" \
  -H "x-sift-admin-secret: change-me-quickstart-admin" \
  -d '{
    "tool": "delete_repo",
    "input": { "repo": "production" },
    "userId": "user-1",
    "orgId": "org-1"
  }'
```

Simulation uses policy and detector logic but skips stateful rate and blast counters.

## Ordering Guidance

Put high-confidence blocks first:

```json
{
  "defaultPolicy": {
    "policies": [],
    "rules": [
      {
        "id": "block-delete-repo",
        "description": "Never allow repository deletion",
        "match": "(toolName) => toolName === 'delete_repo'",
        "action": "block"
      },
      {
        "id": "redact-all-email",
        "description": "Redact PII for email tools",
        "match": "(toolName) => toolName.includes('email')",
        "action": "redact"
      }
    ]
  }
}
```

Because policy is first-match-wins, a broad allow rule near the top can hide later blocks.
