# ai-tools

Paid MCP server: `endpoint_audit` and `token_risk_scan`. Streamable HTTP + x402 USDC.

Live: https://rado-ai-tools.fly.dev/mcp

## Tools

| Tool | Price | What it does |
|---|---|---|
| `endpoint_audit` | $0.02 | GET a URL (SSRF-blocked), score health + MCP/x402 readiness, up to 5 fixes |
| `token_risk_scan` | $0.02 | Format + on-chain `eth_getCode` / nonce on configured chain |
| `ping` | free | Health |

Network default: Base Sepolia (`eip155:84532`). Flip `X402_NETWORK` + `FACILITATOR_URL` + `RPC_URL` for mainnet.

## Testnet endpoints (no payment)

Enabled automatically on Sepolia. Disable with `ENABLE_TEST_ENDPOINTS=false`. Optional `TEST_ENDPOINT_TOKEN`.

```bash
curl -s https://rado-ai-tools.fly.dev/health
curl -s https://rado-ai-tools.fly.dev/test/x402
curl -s -X POST https://rado-ai-tools.fly.dev/test/endpoint_audit \
  -H 'content-type: application/json' \
  -d '{"url":"https://rado-ai-tools.fly.dev/health"}'
curl -s -X POST https://rado-ai-tools.fly.dev/test/token_risk_scan \
  -H 'content-type: application/json' \
  -d '{"token":"0x036CbD53842c5426634e7929541eC2318f3dCF7e"}'
```

Paid path: `POST /mcp` → `tools/list` (free) → `tools/call` without payment should return PaymentRequired. Pay USDC on Base Sepolia to `EVM_ADDRESS`.

## Env

```
EVM_ADDRESS=0xYourPayTo
FACILITATOR_URL=https://x402.org/facilitator
PORT=8080
X402_NETWORK=eip155:84532
X402_PRICE=$0.02
RPC_URL=https://sepolia.base.org
PUBLIC_URL=https://rado-ai-tools.fly.dev
ENABLE_TEST_ENDPOINTS=true
TEST_ENDPOINT_TOKEN=
```

Mainnet facilitator is not `x402.org`. Use CDP or PayAI.

## Deploy

```bash
fly deploy
```

`EVM_ADDRESS` must be set as a Fly secret. Never put a private key on the server.
