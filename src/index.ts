/**
 * @motikolorado/ai-tools — paid MCP server
 * Streamable HTTP + x402. Manual redirects. Validated config.
 */
import "dotenv/config";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { serve } from "@hono/node-server";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { createPaymentWrapper, x402ResourceServer } from "@x402/mcp";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { z } from "zod";
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import type { PaymentWrappedHandler, ToolResult } from "@x402/mcp";

const emptyToUndef = (v: unknown) => (v === "" || v === undefined ? undefined : v);

const parsed = z
  .object({
    EVM_ADDRESS: z.string().regex(/^0x[0-9a-fA-F]{40}$/, "must be a 20-byte EVM address"),
    FACILITATOR_URL: z.string().url(),
    PORT: z.coerce.number().int().min(1).max(65535).default(8080),
    X402_NETWORK: z.string().min(1).default("eip155:84532"),
    X402_PRICE: z.string().regex(/^\$\d+(\.\d{1,6})?$/).default("$0.02"),
    RPC_URL: z.string().url().default("https://sepolia.base.org"),
    PUBLIC_URL: z.string().url().default("https://rado-ai-tools.fly.dev"),
    ENABLE_TEST_ENDPOINTS: z.enum(["true", "false"]).default("false"),
    TEST_ENDPOINT_TOKEN: z.preprocess(emptyToUndef, z.string().default("")),
    METRICS_TOKEN: z.preprocess(emptyToUndef, z.string().min(16).optional()),
  })
  .safeParse(process.env);

if (!parsed.success) {
  console.error("Invalid configuration:", parsed.error.flatten().fieldErrors);
  process.exit(1);
}

const cfg = parsed.data;
const SERVER_NAME = "ai-tools";
const SERVER_VERSION = "1.2.1";
const ASSET = "USDC";
const ASSET_VERSION = "2";
const PUBLIC_URL = cfg.PUBLIC_URL.replace(/\/$/, "");
const NETWORK = cfg.X402_NETWORK as `${string}:${string}`;
const IS_TESTNET = NETWORK.includes("84532") || NETWORK.toLowerCase().includes("sepolia");
const TEST_ENDPOINTS = cfg.ENABLE_TEST_ENDPOINTS === "true" && IS_TESTNET;
const USDC_SEPOLIA = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const MAX_BODY_BYTES = 64 * 1024;
const FETCH_TIMEOUT_MS = 8000;
const MAX_REDIRECTS = 3;

const metrics = {
  startedAt: new Date().toISOString(),
  mcpRequests: 0,
  mcpErrors: 0,
  testCalls: 0,
  toolCalls: 0,
  toolErrors: 0,
  paymentsSettled: 0,
};

const rateBuckets = new Map<string, { n: number; t: number }>();
setInterval(() => {
  const cutoff = Date.now() - 120_000;
  for (const [key, value] of rateBuckets) if (value.t < cutoff) rateBuckets.delete(key);
}, 60_000).unref();

const CORS: Record<string, string> = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, HEAD, POST, DELETE, OPTIONS",
  "access-control-allow-headers":
    "content-type, authorization, mcp-session-id, mcp-protocol-version, payment-signature, payment-required, x-payment, x402-payment",
  "access-control-expose-headers": "mcp-session-id, payment-required, payment-response, www-authenticate",
};

function json(data: unknown, status = 200, method = "GET"): Response {
  const body = Buffer.from(JSON.stringify(data));
  const headers: Record<string, string> = {
    "content-type": "application/json; charset=utf-8",
    "content-length": String(body.byteLength),
    "cache-control": "no-store",
    ...CORS,
  };
  if (method === "HEAD") return new Response(null, { status, headers });
  return new Response(body, { status, headers });
}
