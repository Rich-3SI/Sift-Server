# Quickstart

This quickstart runs Sift Server in front of a tiny MCP upstream so you can see policy enforcement and audit logging without connecting to real company systems.

## Requirements

- Docker with Docker Compose.
- Node.js 22 or newer.

Check your local versions:

```bash
node --version
docker --version
docker compose version
```

`node --version` should print `v22.x` or newer. Older Node versions may install dependencies with warnings or fail on newer runtime APIs.

## Clone The Repo

```bash
git clone https://github.com/Rich-3SI/Sift-Server.git
cd Sift-Server
```

## Start The Stack

From the repo root:

```bash
docker compose -f deploy/quickstart/docker-compose.yml up --build
```

Sift Server will expose:

- MCP endpoint: `http://127.0.0.1:18080/mcp`
- Admin endpoint: `http://127.0.0.1:18081`

Quickstart credentials:

- API key: `sk-sift-quickstart-dev`
- Admin secret: `change-me-quickstart-admin`

These are local demo values. Replace them before using Sift on any shared network.

## Run The Smoke Test

In another terminal:

```bash
npm install
npm run quickstart:test
```

Successful output looks like:

```text
[PASS] /healthz reports alive
[PASS] /readyz reports ready
[PASS] MCP client connects with quickstart API key
[PASS] Allowed status tool reaches upstream
[PASS] Allowed echo tool reaches upstream
[PASS] Blocked delete_repo returns MCP error result
[PASS] Stats counted allowed and blocked calls
```

The smoke test verifies:

- Health and readiness endpoints.
- MCP auth rejection for missing or invalid API keys.
- Authenticated MCP connection.
- Tool listing.
- Allowed `status` and `echo` calls.
- Blocked `delete_repo` call.
- Admin policy simulation.
- Stats counters.
- JSONL audit export.

## Inspect Audit Logs

The quickstart writes local SQLite and JSONL audit logs inside the Sift Server container volume.

```bash
docker compose -f deploy/quickstart/docker-compose.yml exec sift-server \
  sh -lc "tail -n 20 /data/audit.jsonl"
```

## Stop The Stack

```bash
docker compose -f deploy/quickstart/docker-compose.yml down
```

Remove the persisted audit volume:

```bash
docker compose -f deploy/quickstart/docker-compose.yml down -v
```

## Next Steps

- Read [configuration.md](configuration.md) to connect real upstream MCP servers.
- Read [installation.md](installation.md) to deploy Sift Server in a production-oriented environment.
- Read [policy-examples.md](policy-examples.md) to write policies.
- Read [security-model.md](security-model.md) before exposing Sift Server to a team.
