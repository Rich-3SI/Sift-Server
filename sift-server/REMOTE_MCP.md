# Remote MCP with Sift Server

Sift Server is the hosted Streamable HTTP deployment target for cloud and web agents.
It exposes one authenticated MCP endpoint:

```text
https://your-sift-server.example.com/mcp
```

Use this path for clients that cannot run a local stdio proxy, including hosted IDE agents, web agents, and other remote MCP consumers.

## Start Sift Server

```bash
sift-server --config ./sift-server.config.json
```

Required environment for enterprise policy sync, audit forwarding, and heartbeat:

```env
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your-supabase-anon-key
SIFT_ORG_ID=your-org-id
SIFT_DB_PATH=/var/lib/sift
SIFT_ADMIN_SECRET=long-random-admin-secret
```

## Minimal Config

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
        "key": "sk_sift_replace_me",
        "userId": "cloud-agent",
        "orgId": "your-org-id",
        "email": "agent@company.com"
      }
    ]
  },
  "upstreams": [
    {
      "name": "github",
      "url": "https://your-upstream-mcp.example.com/mcp",
      "headers": {
        "Authorization": "Bearer upstream-fastmcp-token"
      }
    }
  ],
  "defaultPolicy": {
    "policies": ["audit-only-mode"],
    "rules": []
  },
  "rateLimitPerMinute": 60,
  "blastRadiusLimit": 10
}
```

## Client Snippets

Most JSON-based MCP clients:

```json
{
  "mcpServers": {
    "sift-remote": {
      "type": "http",
      "url": "https://your-sift-server.example.com/mcp",
      "headers": {
        "Authorization": "Bearer sk_sift_replace_me"
      }
    }
  }
}
```

VS Code and Copilot agent mode:

```json
{
  "servers": {
    "sift-remote": {
      "type": "http",
      "url": "https://your-sift-server.example.com/mcp",
      "headers": {
        "Authorization": "Bearer sk_sift_replace_me"
      }
    }
  }
}
```

## Security Notes

Use API-key auth for any internet-reachable server, terminate TLS before traffic reaches Sift Server, and issue separate API keys per user, agent, or team so audit rows retain a useful identity. Keep `/stats`, `/sessions`, and `/admin/*` on an internal-only admin port and set `SIFT_ADMIN_SECRET` for authenticated operator access.

See `deploy/caddy/` for a minimal TLS reverse proxy example.
