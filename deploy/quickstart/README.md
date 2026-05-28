# Sift Server Quickstart

This stack runs Sift Server in front of a tiny authenticated MCP upstream.

Requirements:

- Docker with Docker Compose.
- Node.js 22 or newer.

From the repo root:

```bash
docker compose -f deploy/quickstart/docker-compose.yml up --build
```

Then, in another terminal:

```bash
npm install
npm run quickstart:test
```

You should see `[PASS]` for each smoke-test check.

The quickstart binds only to localhost:

- MCP: `http://127.0.0.1:18080/mcp`
- Admin: `http://127.0.0.1:18081`

Local demo credentials:

- API key: `sk-sift-quickstart-dev`
- Admin secret: `change-me-quickstart-admin`

Do not use these values on a shared network.
