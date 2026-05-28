# Sift Server behind Caddy

Sift Server intentionally does not terminate TLS. Put it behind an existing load balancer, ingress controller, or reverse proxy and expose only `/mcp` to MCP clients.

This example assumes:

- Sift Server MCP listener: `127.0.0.1:8080`
- Sift Server admin listener: `127.0.0.1:8081`
- Public DNS name: `sift-server.example.com`

Replace the domain, email, and admin `remote_ip` ranges before production use.

```bash
caddy run --config sift-server/deploy/caddy/Caddyfile
```

Set `SIFT_ADMIN_SECRET` on the Sift Server process. Caddy restricts admin paths by network, while Sift Server also requires `x-sift-admin-secret` for `/stats`, `/sessions`, and `/admin/*`.
