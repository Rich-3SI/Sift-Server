# Installation

This guide walks through running Sift Server in a production-oriented environment. Use the [quickstart](quickstart.md) first if you only want to see Sift block and allow demo tools locally.

## Deployment Model

Sift Server is an HTTP MCP gateway. In production it usually runs like this:

```text
MCP client
  -> TLS reverse proxy or load balancer
  -> Sift Server /mcp
  -> upstream MCP servers
```

Sift Server exposes two listeners:

| Listener | Default | Purpose |
|---|---:|---|
| MCP | `8080` | Authenticated MCP client traffic |
| Admin | `8081` | Health, readiness, stats, sessions, and policy simulation |

Expose `/mcp` to approved MCP clients. Keep admin endpoints on a trusted network and set `SIFT_ADMIN_SECRET`.

## Prerequisites

Required:

- Linux host, VM, or container platform.
- Docker with Docker Compose, or Node.js 22 or newer.
- One or more upstream MCP servers.
- A plan for TLS termination.
- A secret for `SIFT_ADMIN_SECRET`.
- At least one API key or a JWT/JWKS identity provider.

Check versions:

```bash
node --version
docker --version
docker compose version
```

`node --version` should print `v22.x` or newer when running Sift outside Docker.

Generate local secrets:

```bash
openssl rand -hex 32
```

Use different values for Sift API keys, admin secrets, upstream MCP credentials, and audit webhook credentials.

## Install From Source

Until official release artifacts are published, build Sift Server from the repository.

```bash
git clone https://github.com/Rich-3SI/Sift-Server.git
cd Sift-Server
npm ci
npm run build
```

Run tests before deploying a modified build:

```bash
npm run typecheck
npm test
```

## Configure Sift Server

Start from the example config:

```bash
cp sift-server/sift-server.config.example.json sift-server.config.json
```

At minimum, replace:

- API keys under `auth.apiKeys`.
- `userId`, `orgId`, and `email` values.
- Upstream MCP server definitions.
- Policy templates and custom rules.
- Audit destinations.

Example production shape:

```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 8080,
    "adminPort": 8081
  },
  "auth": {
    "mode": "api-key",
    "apiKeys": [
      {
        "key": "replace-with-long-random-api-key",
        "userId": "engineering-agent",
        "orgId": "acme",
        "email": "engineering@example.com",
        "description": "Engineering agent access"
      }
    ]
  },
  "upstreams": [
    {
      "name": "internal-api",
      "url": "http://internal-mcp:3000/mcp",
      "headers": {
        "Authorization": "Bearer replace-with-upstream-token"
      }
    }
  ],
  "defaultPolicy": {
    "policies": ["redact-credentials"],
    "rules": [
      {
        "id": "block-dangerous-delete",
        "match": "(toolName) => /delete|destroy|drop/i.test(toolName)",
        "action": "block",
        "reason": "Destructive tools require a separate approval path"
      }
    ]
  },
  "audit": {
    "jsonlPath": "/data/audit.jsonl",
    "webhooks": []
  },
  "metadataScan": {
    "enabled": true,
    "action": "warn",
    "includeSchemas": true
  },
  "maxSessions": 1000,
  "sessionTtlMinutes": 30,
  "blastRadiusLimit": 10,
  "rateLimitPerMinute": 60
}
```

Do not commit production secrets to Git. Store production configs in your secret manager, deployment system, or encrypted infrastructure repository.

## Run With Docker

Build the image:

```bash
docker build -f sift-server/Dockerfile -t sift-server:latest .
```

Run it with persistent audit storage:

```bash
docker volume create sift_data

docker run --name sift-server \
  --restart unless-stopped \
  -p 127.0.0.1:8080:8080 \
  -p 127.0.0.1:8081:8081 \
  -v "$PWD/sift-server.config.json:/etc/sift-server/config.json:ro" \
  -v sift_data:/data \
  -e SIFT_DB_PATH=/data \
  -e SIFT_ADMIN_SECRET=replace-with-long-random-admin-secret \
  sift-server:latest
```

The example binds both ports to `127.0.0.1` so a reverse proxy can front the service. If you bind to a public interface, expose only the MCP path through a protected TLS layer and keep admin paths restricted.

## Run With Docker Compose

Use this as a starting point for a production Compose deployment:

```yaml
services:
  sift-server:
    build:
      context: .
      dockerfile: sift-server/Dockerfile
    restart: unless-stopped
    environment:
      NODE_ENV: production
      SIFT_DB_PATH: /data
      SIFT_ADMIN_SECRET: replace-with-long-random-admin-secret
    ports:
      - "127.0.0.1:8080:8080"
      - "127.0.0.1:8081:8081"
    volumes:
      - ./sift-server.config.json:/etc/sift-server/config.json:ro
      - sift_data:/data
    healthcheck:
      test: ["CMD", "node", "-e", "fetch('http://127.0.0.1:8081/readyz').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"]
      interval: 10s
      timeout: 3s
      retries: 12

volumes:
  sift_data:
```

Start it:

```bash
docker compose up --build -d
```

View logs:

```bash
docker compose logs -f sift-server
```

Stop it:

```bash
docker compose down
```

## Run With Node.js

For a systemd, process manager, or development-style deployment:

```bash
npm ci
npm run build

SIFT_DB_PATH=/var/lib/sift \
SIFT_ADMIN_SECRET=replace-with-long-random-admin-secret \
node sift-server/dist/sift-server/src/index.js --config ./sift-server.config.json
```

Make sure the runtime user can write to `SIFT_DB_PATH` and the JSONL audit path if configured.

## Put Sift Behind TLS

Sift Server intentionally does not terminate TLS. Put it behind a load balancer, ingress controller, or reverse proxy.

The repo includes a Caddy example:

```bash
cp sift-server/deploy/caddy/Caddyfile ./Caddyfile
```

Before production use, edit:

- Domain name.
- ACME email.
- Admin source IP ranges.
- Upstream addresses if Sift does not listen on `127.0.0.1:8080` and `127.0.0.1:8081`.

Run Caddy:

```bash
caddy run --config ./Caddyfile
```

Only `/mcp` should be broadly reachable by approved clients. `/stats`, `/sessions`, `/admin/*`, `/healthz`, and `/readyz` should be limited to trusted networks.

## Connect MCP Clients

Use the MCP URL exposed by your reverse proxy:

```text
https://sift-server.example.com/mcp
```

Most HTTP MCP clients need:

```json
{
  "mcpServers": {
    "sift": {
      "type": "http",
      "url": "https://sift-server.example.com/mcp",
      "headers": {
        "Authorization": "Bearer replace-with-sift-api-key"
      }
    }
  }
}
```

Issue separate Sift credentials per user, agent, team, or workload. Shared keys make audit trails much less useful.

## Verify The Installation

Health:

```bash
curl -fsS http://127.0.0.1:8081/healthz
```

Readiness:

```bash
curl -fsS http://127.0.0.1:8081/readyz
```

Stats:

```bash
curl -fsS \
  -H "x-sift-admin-secret: replace-with-long-random-admin-secret" \
  http://127.0.0.1:8081/stats
```

Audit log:

```bash
tail -n 20 /path/to/audit.jsonl
```

If Sift is running in Docker with the examples above:

```bash
docker compose exec sift-server sh -lc "tail -n 20 /data/audit.jsonl"
```

You should verify:

- Missing or invalid bearer tokens are rejected.
- A known-safe tool call is allowed.
- A known-dangerous policy test is blocked.
- Audit rows include the expected `userId`, `orgId`, tool name, action, and session ID.
- Admin endpoints require `x-sift-admin-secret`.

## Production Checklist

Before exposing Sift Server to a team:

- Replace every demo credential.
- Use long random API keys or JWT/JWKS auth.
- Keep `/mcp` behind TLS.
- Keep admin endpoints on a trusted network.
- Set `SIFT_ADMIN_SECRET`.
- Use persistent storage for `/data`.
- Export audits to JSONL, webhooks, or your logging platform.
- Issue separate credentials per user, agent, or team.
- Run upstream MCP servers with least privilege.
- Start with conservative block rules for destructive tools.
- Monitor blocked calls before loosening policy.
- Test upgrades in a staging or lab environment before production.

## Updating

Pull the latest code, rebuild, and run the test suite before replacing a running deployment:

```bash
git pull
npm ci
npm run typecheck
npm test
docker build -f sift-server/Dockerfile -t sift-server:latest .
```

For Compose deployments:

```bash
docker compose up --build -d
docker compose logs -f sift-server
```

Keep a copy of the previous image or commit hash so you can roll back quickly if a policy, config, or upstream behavior changes unexpectedly.
