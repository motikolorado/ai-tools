/**
 * @motikolorado/ai-tools — paid MCP server
 * Streamable HTTP + x402. Manual redirects. Validated config.
 */
import "dotenv/config";
import http from "node:http";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { createPaymentWrapper, x402ResourceServer } from "@x402/mcp";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { z } from "zod";
import type { PaymentWrappedHandler, ToolResult } from "@x402/mcp";
import { incomingToRequest, writeNodeResponse } from "./http.js";
import { assertSafeUrl } from "./ssrf.js";
import { runEndpointAudit, runTokenRiskScan as scanToken } from "./tools.js";

export { assertSafeUrl };

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
const SERVER_VERSION = "1.2.2";
const ASSET = "USDC";
const ASSET_VERSION = "2";
const PUBLIC_URL = cfg.PUBLIC_URL.replace(/\/$/, "");
const NETWORK = cfg.X402_NETWORK as `${string}:${string}`;
const IS_TESTNET = NETWORK.includes("84532") || NETWORK.toLowerCase().includes("sepolia");
const TEST_ENDPOINTS = cfg.ENABLE_TEST_ENDPOINTS === "true" && IS_TESTNET;
const USDC_SEPOLIA = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";

export async function runTokenRiskScan(args: { token: string }): Promise<ToolResult> {
  return scanToken(args, { rpcUrl: cfg.RPC_URL, network: NETWORK });
}

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

function json(data: unknown, status = 200): Response {
  const body = Buffer.from(JSON.stringify(data));
  return new Response(body, {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "content-length": String(body.byteLength),
      "cache-control": "no-store",
      ...CORS,
    },
  });
}

function clientIp(req: Request): string {
  return req.headers.get("fly-client-ip") || req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "unknown";
}

function rateLimit(key: string, max: number, windowMs: number): boolean {
  const now = Date.now();
  const b = rateBuckets.get(key);
  if (!b || now - b.t >= windowMs) {
    rateBuckets.set(key, { n: 1, t: now });
    return true;
  }
  if (b.n >= max) return false;
  b.n++;
  return true;
}

type ToolSchema = Record<string, z.ZodTypeAny>;

const toolCatalog: Array<{
  alias: string;
  description: string;
  schema: ToolSchema;
  inputSchema: Record<string, unknown>;
  example: Record<string, unknown>;
  handler: (a: Record<string, unknown>) => Promise<ToolResult>;
}> = [
  {
    alias: "endpoint_audit",
    description: "Audit a URL for availability and MCP/x402 discovery signals. SSRF protected. Price: $0.02 USDC.",
    schema: { url: z.string().url().describe("HTTP or HTTPS URL to audit") },
    inputSchema: { type: "object", properties: { url: { type: "string" } }, required: ["url"] },
    example: { url: `${PUBLIC_URL}/health` },
    handler: async (a: Record<string, unknown>) => runEndpointAudit({ url: String(a.url || "") }),
  },
  {
    alias: "token_risk_scan",
    description: "Perform a conservative on-chain contract-address snapshot. Not a security or honeypot detector. Price: $0.02 USDC.",
    schema: { token: z.string().min(4) },
    inputSchema: { type: "object", properties: { token: { type: "string" } }, required: ["token"] },
    example: { token: USDC_SEPOLIA },
    handler: async (a: Record<string, unknown>) => runTokenRiskScan({ token: String(a.token || "") }),
  },
];

function card() {
  return {
    name: SERVER_NAME,
    description: "Paid MCP tools for endpoint auditing and conservative on-chain address inspection.",
    repository: "https://github.com/motikolorado/ai-tools",
    homepage: PUBLIC_URL,
    version: SERVER_VERSION,
    license: "MIT",
    pricing: {
      model: "pay-per-call",
      currency: ASSET,
      pricePerCall: cfg.X402_PRICE.slice(1),
      network: cfg.X402_NETWORK,
      currencyContract: IS_TESTNET ? USDC_SEPOLIA : USDC_BASE,
    },
    tools: toolCatalog.map((t) => ({ name: t.alias, description: t.description, pricePerCall: cfg.X402_PRICE.slice(1) })),
  };
}

function buildMcpServer(
  resourceServer: InstanceType<typeof x402ResourceServer>,
  accepts: Awaited<ReturnType<InstanceType<typeof x402ResourceServer>["buildPaymentRequirements"]>>,
) {
  const server = new McpServer({ name: SERVER_NAME, version: SERVER_VERSION });
  for (const tool of toolCatalog) {
    const paid = createPaymentWrapper(resourceServer, {
      accepts,
      resource: { url: `mcp://tool/${tool.alias}`, description: tool.description },
      extensions: {
        bazaar: {
          info: { type: "mcp", toolName: tool.alias, description: tool.description, transport: "streamable-http", url: `${PUBLIC_URL}/mcp` },
          schema: { inputSchema: tool.inputSchema, example: tool.example },
        },
      },
    } as Parameters<typeof createPaymentWrapper>[1]);
    const wrapped: PaymentWrappedHandler<Record<string, unknown>> = async (args) => {
      metrics.toolCalls++;
      try {
        return (await tool.handler(args)) as ToolResult;
      } catch (e) {
        metrics.toolErrors++;
        throw e;
      }
    };
    server.tool(tool.alias, tool.description, tool.schema, paid(wrapped));
  }
  server.tool("ping", "Free health check", {}, async () => ({
    content: [{ type: "text" as const, text: "pong" }],
  }));
  return server;
}

function authorized(req: Request, kind: "test" | "metrics"): Response | null {
  if (kind === "test" && !TEST_ENDPOINTS) return json({ error: "not found" }, 404);
  const token = kind === "metrics" ? cfg.METRICS_TOKEN : cfg.TEST_ENDPOINT_TOKEN;
  if (kind === "metrics" && !token) return json({ error: "not found" }, 404);
  if (token && req.headers.get("authorization") !== `Bearer ${token}`) return json({ error: "unauthorized" }, 401);
  if (kind === "test" && !rateLimit(`test:${clientIp(req)}`, 20, 60_000)) return json({ error: "rate limited" }, 429);
  return null;
}

async function handleRequest(
  req: Request,
  resource: InstanceType<typeof x402ResourceServer>,
  accepts: Awaited<ReturnType<InstanceType<typeof x402ResourceServer>["buildPaymentRequirements"]>>,
): Promise<Response> {
  const url = new URL(req.url);
  const path = url.pathname;
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });

  if (path === "/") {
    return json({
      name: SERVER_NAME,
      version: SERVER_VERSION,
      mcp: `${PUBLIC_URL}/mcp`,
      health: `${PUBLIC_URL}/health`,
      card: `${PUBLIC_URL}/.well-known/mcp/server-card.json`,
      testEndpoints: TEST_ENDPOINTS,
    });
  }

  if (path === "/health") {
    return json({
      status: "ok",
      version: SERVER_VERSION,
      network: cfg.X402_NETWORK,
      tools: toolCatalog.map((t) => t.alias).concat(["ping"]),
    });
  }

  if (path === "/metrics") {
    const denied = authorized(req, "metrics");
    return denied || json({ ...metrics, uptimeSec: Math.floor((Date.now() - Date.parse(metrics.startedAt)) / 1000) });
  }

  if (path === "/.well-known/mcp/server-card.json" || path === "/server-card.json") return json(card());

  if (path === "/test" || path.startsWith("/test/")) {
    const denied = authorized(req, "test");
    if (denied) return denied;
    if (path === "/test") {
      return json({
        name: SERVER_NAME,
        version: SERVER_VERSION,
        testEndpoints: true,
        routes: ["/test/x402", "/test/endpoint_audit", "/test/token_risk_scan"],
      });
    }
    if (path === "/test/x402") {
      metrics.testCalls++;
      return json({ network: NETWORK, payTo: cfg.EVM_ADDRESS, price: cfg.X402_PRICE, accepts });
    }
    if (path === "/test/endpoint_audit" && req.method === "POST") {
      metrics.testCalls++;
      const body = (await req.json().catch(() => null)) as { url?: string } | null;
      if (!body?.url) return json({ error: "JSON body required: { url }" }, 400);
      const result = await runEndpointAudit({ url: body.url });
      const text = result.content[0] && "text" in result.content[0] ? String(result.content[0].text) : "{}";
      return json({ test: true, paid: false, result: JSON.parse(text) });
    }
    if (path === "/test/token_risk_scan" && req.method === "POST") {
      metrics.testCalls++;
      const body = (await req.json().catch(() => null)) as { token?: string } | null;
      if (!body?.token) return json({ error: "JSON body required: { token }" }, 400);
      const result = await runTokenRiskScan({ token: body.token });
      const text = result.content[0] && "text" in result.content[0] ? String(result.content[0].text) : "{}";
      return json({ test: true, paid: false, result: JSON.parse(text) });
    }
    return json({ error: "not found" }, 404);
  }

  if (path === "/mcp") {
    if (req.method === "GET" || req.method === "HEAD") {
      return json({ error: "Use POST /mcp for Streamable HTTP JSON-RPC. GET SSE is disabled." }, 405);
    }
    if (req.method !== "POST" && req.method !== "DELETE") {
      return json({ error: "method not allowed" }, 405);
    }
    if (!rateLimit(`mcp:${clientIp(req)}`, 120, 60_000)) return json({ error: "rate limited" }, 429);
    metrics.mcpRequests++;
    const server = buildMcpServer(resource, accepts);
    const transport = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    await server.connect(transport);
    try {
      const response = await transport.handleRequest(req);
      const headers = new Headers(response.headers);
      Object.entries(CORS).forEach(([k, v]) => {
        if (!headers.has(k)) headers.set(k, v);
      });
      headers.delete("content-length");
      return new Response(response.body, { status: response.status, headers });
    } catch {
      metrics.mcpErrors++;
      return json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal MCP error" }, id: null }, 500);
    }
  }

  return json({ error: "not found" }, 404);
}

async function main() {
  const facilitator = new HTTPFacilitatorClient({ url: cfg.FACILITATOR_URL });
  const resource = new x402ResourceServer(facilitator);
  resource.register(NETWORK, new ExactEvmScheme());
  await resource.initialize();
  const accepts = await resource.buildPaymentRequirements({
    scheme: "exact",
    network: NETWORK,
    payTo: cfg.EVM_ADDRESS as `0x${string}`,
    price: cfg.X402_PRICE,
    extra: { name: ASSET, version: ASSET_VERSION },
  });

  const server = http.createServer((req, res) => {
    const incoming = incomingToRequest(req);
    handleRequest(incoming, resource, accepts)
      .then((response) => writeNodeResponse(res, response, incoming.method))
      .catch((error) => {
        metrics.mcpErrors++;
        const body = Buffer.from(
          JSON.stringify({ error: "internal error", message: error instanceof Error ? error.message.slice(0, 160) : "unknown" }),
        );
        if (!res.headersSent) {
          res.writeHead(500, {
            "content-type": "application/json; charset=utf-8",
            "content-length": body.byteLength,
            ...CORS,
          });
        }
        res.end(body);
      });
  });

  server.keepAliveTimeout = 65_000;
  server.headersTimeout = 66_000;
  server.listen(cfg.PORT, "0.0.0.0", () => {
    console.log(`${SERVER_NAME} v${SERVER_VERSION} on 0.0.0.0:${cfg.PORT}`);
  });
}

if (process.env.NODE_ENV !== "test") {
  main().catch((error) => {
    console.error("Fatal startup error", error instanceof Error ? error.message : error);
    process.exit(1);
  });
}
