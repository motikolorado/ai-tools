# ai-tools

Paid MCP server providing `endpoint_audit` and `token_risk_scan` over Streamable HTTP with x402 USDC payments.

## Security and production posture

- Redirects are manually followed and every destination is revalidated for SSRF.
- Private, loopback, link-local, mapped IPv4/IPv6 addresses and unsafe internal hostnames are rejected.
- Requests have timeouts, redirect limits, and a 64 KiB response limit.
- Test routes are disabled by default and require a test token when configured.
- Metrics are private unless `METRICS_TOKEN` is configured.
- Startup configuration is validated before the server starts.
- CI runs type checking, tests, dependency auditing, and a Docker build.

## Tools

| Tool | Price | Purpose |
|---|---:|---|
| `endpoint_audit` | $0.02 | Availability and MCP/x402 discovery signals for a URL. This is not a penetration test. |
| `token_risk_scan` | $0.02 | Conservative address/bytecode snapshot. This is not a honeypot or security detector. |
| `ping` | free | Health check |

## Configuration

Copy `.env.example`, set `EVM_ADDRESS`, `FACILITATOR_URL`, and `RPC_URL`, then build and start:

```bash
npm ci
npm run build
npm test
npm start
```

For local test routes, explicitly set `ENABLE_TEST_ENDPOINTS=true` and configure `TEST_ENDPOINT_TOKEN`. Never enable them publicly without authentication. `METRICS_TOKEN` must be at least 16 characters to expose `/metrics`.

Default network is Base Sepolia (`eip155:84532`). Never put a private key on the server; only the receiving address is required.

## Deployment

```bash
fly secrets set EVM_ADDRESS=0x... FACILITATOR_URL=https://x402.org/facilitator RPC_URL=https://sepolia.base.org
fly deploy
```
