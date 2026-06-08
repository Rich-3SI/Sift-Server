# Configuration

Sift Server uses a JSON config file. The example lives at:

```text
sift-server/sift-server.config.example.json
```

## Minimal Shape

```json
{
  "server": {
    "port": 8080,
    "host": "0.0.0.0",
    "adminPort": 8081,
    "adminHost": "127.0.0.1"
  },
  "auth": {
    "mode": "api-key",
    "apiKeys": [
      {
        "key": "replace-with-random-value",
        "userId": "user-1",
        "orgId": "org-1",
        "email": "user@example.com"
      }
    ]
  },
  "upstreams": [
    {
      "name": "filesystem",
      "command": ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp/sandbox"]
    }
  ],
  "defaultPolicy": {
    "policies": ["block-filesystem-writes"],
    "rules": []
  }
}
```

## Server

| Field | Default | Description |
|---|---:|---|
| `server.port` | `8080` | MCP HTTP endpoint port |
| `server.host` | `0.0.0.0` | MCP bind host |
| `server.adminPort` | `8081` | Health/admin endpoint port |
| `server.adminHost` | `127.0.0.1` | Health/admin bind host |
| `maxSessions` | `1000` | Maximum active MCP sessions |
| `sessionTtlMinutes` | `30` | Idle session timeout |
| `blastRadiusLimit` | `10` | Destructive calls per scoped session before blocking |
| `rateLimitPerMinute` | `60` | Calls per user per minute |

## Auth

Supported modes:

- `api-key`
- `jwt`
- `api-key-or-jwt`
- `none`

Use `none` only for local testing behind trusted controls.

### API Keys

```json
{
  "auth": {
    "mode": "api-key",
    "apiKeys": [
      {
        "key": "replace-with-random-value",
        "userId": "alice",
        "orgId": "acme",
        "email": "alice@example.com",
        "expiresAt": "2026-12-31T23:59:59.000Z",
        "revoked": false
      }
    ]
  }
}
```

### JWT

```json
{
  "auth": {
    "mode": "jwt",
    "jwt": {
      "issuer": "https://idp.example.com/",
      "audience": "sift-server",
      "jwksUrl": "https://idp.example.com/.well-known/jwks.json",
      "userIdClaim": "sub",
      "orgIdClaim": "org_id",
      "emailClaim": "email",
      "allowedAlgorithms": ["RS256"]
    }
  }
}
```

For local development only, JWT config can use `hmacSecret` with `HS256`.
JWTs must include `exp`, and production configs must set expected `issuer` and `audience`.
Local-only overrides are available as `allowMissingExpiration`, `allowMissingIssuer`, and
`allowMissingAudience`, but they should not be used for shared or production servers.

## Upstreams

Stdio upstream:

```json
{
  "name": "filesystem",
  "command": ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp/sandbox"]
}
```

HTTP upstream:

```json
{
  "name": "internal-api",
  "url": "http://internal-mcp:3000/mcp",
  "headers": {
    "Authorization": "Bearer replace-with-upstream-token"
  }
}
```

## Audit Export

```json
{
  "audit": {
    "jsonlPath": "/var/log/sift/audit.jsonl",
    "webhooks": [
      {
        "url": "https://collector.example.com/sift/audits",
        "bearerToken": "replace-with-collector-token",
        "timeoutMs": 5000
      }
    ]
  }
}
```

SQLite audit is enabled by default through the local audit handler. Use `SIFT_DB_PATH` to choose the directory.

## Metadata Scan

```json
{
  "metadataScan": {
    "enabled": true,
    "action": "warn",
    "includeSchemas": true,
    "maxStringLength": 20000
  }
}
```

Actions:

- `warn`: audit unsafe metadata but return it.
- `block`: hide unsafe listed metadata and reject unsafe returned metadata.

## Environment Variables

| Variable | Description |
|---|---|
| `SIFT_DB_PATH` | Directory for local SQLite audit database |
| `SIFT_ADMIN_SECRET` | Required for `/stats`, `/sessions`, and `/admin/*` |
