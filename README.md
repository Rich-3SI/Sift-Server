# Sift Server

**Open-source MCP security gateway for AI agents.**

Sift Server sits between AI agents and Model Context Protocol (MCP) servers. It authenticates callers, scans MCP metadata, enforces tool-use policies, inspects outputs, and writes audit logs before agent actions reach internal systems.

Use it when you want AI agents to use tools without giving every agent unlimited trust.

## What It Does

- Aggregates multiple MCP upstreams behind one HTTP MCP endpoint.
- Enforces allow, block, and redact policies before tool execution.
- Detects PII and prompt-injection patterns in inputs, outputs, prompts, resources, and tool metadata.
- Supports static API keys and JWT/OIDC-style bearer tokens.
- Writes local SQLite audits and exports JSONL or webhook events.
- Exposes health, readiness, stats, session, disconnect, and policy simulation endpoints.

## Quickstart

Run Sift Server in front of a tiny demo MCP upstream:

```bash
git clone https://github.com/Rich-3SI/Sift-Server.git
cd Sift-Server
```

Check prerequisites:

```bash
node --version           # v22 or newer
docker --version
docker compose version
```

Start the demo stack:

```bash
docker compose -f deploy/quickstart/docker-compose.yml up --build
```

In another terminal:

```bash
npm install
npm run quickstart:test
```

The smoke test prints `[PASS]` for each check when Sift Server is working.

The quickstart proves:

| Tool | Expected result |
|---|---|
| `status` | allowed |
| `echo` | allowed |
| `delete_repo` | blocked by policy |

Endpoints:

- MCP: `http://127.0.0.1:18080/mcp`
- Admin: `http://127.0.0.1:18081`
- Demo API key: `sk-sift-quickstart-dev`
- Demo admin secret: `change-me-quickstart-admin`

See [docs/quickstart.md](docs/quickstart.md) for the full walkthrough.

## Development

Requires Node.js 22 or newer.

```bash
npm install
npm run typecheck
npm test
```

Build the server:

```bash
npm run build
```

Build the Docker image:

```bash
npm run docker:build
```

## Documentation

- [Quickstart](docs/quickstart.md)
- [Installation](docs/installation.md)
- [Architecture](docs/architecture.md)
- [Security model](docs/security-model.md)
- [Configuration](docs/configuration.md)
- [Policy examples](docs/policy-examples.md)
- [Remote MCP deployment notes](sift-server/REMOTE_MCP.md)

## Repository Layout

| Path | Purpose |
|---|---|
| `sift-server/` | HTTP MCP gateway, auth, config, admin, and health code |
| `src/` | Shared policy engine, audit handlers, metadata scanner, templates, and upstream pool |
| `deploy/quickstart/` | Public Docker quickstart |
| `test/` | Shared core tests used by Sift Server |
| `sift-server/test/` | Sift Server integration and HTTP-layer tests |

## Production Notes

- Bind the admin port to a trusted network.
- Set `SIFT_ADMIN_SECRET`.
- Replace all demo credentials.
- Prefer JWT/JWKS for managed identity.
- Export audits to JSONL, webhooks, or your logging stack.
- Run upstream MCP servers with least privilege.

## Project Status

Sift Server is early and evolving. The current focus is a lightweight, vendor-neutral MCP security gateway that teams can run, inspect, and extend.

## Security

Please do not report vulnerabilities in public issues. See [SECURITY.md](SECURITY.md).

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).

Maintained by 3rd Star Industries LLC.
