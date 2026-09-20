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
const SERVER_VERSION = "1.2.0";
const ASSET = "USDC";
const ASSET_VERSION = "2";
const PUBLIC_URL = cfg.PUBLIC_URL.replace(/\/$/, "");
const IS_TESTNET = cfg.X402_NETWORK.includes("84532") || cfg.X402_NETWORK.toLowerCase().includes("sepolia");
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
  "access-control-allow-methods": "GET, POST, DELETE, OPTIONS",
  "access-control-allow-headers":
    "content-type, authorization, mcp-session-id, mcp-protocol-version, payment-signature, payment-required, x-payment, x402-payment",
  "access-control-expose-headers": "mcp-session-id, payment-required, payment-response, www-authenticate",
};

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...CORS },
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

function isPrivateIp(raw: string): boolean {
  const ip = raw.replace(/^\[|\]$/g, "").toLowerCase();
  if (ip.startsWith("::ffff:")) return isPrivateIp(ip.slice(7));
  if (isIP(ip) === 4) {
    const p = ip.split(".").map(Number);
    return (
      p[0] === 0 ||
      p[0] === 10 ||
      p[0] === 127 ||
      (p[0] === 169 && p[1] === 254) ||
      (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
      (p[0] === 192 && p[1] === 168) ||
      (p[0] === 100 && p[1] >= 64 && p[1] <= 127)
    );
  }
  if (isIP(ip) === 6) {
    return ip === "::1" || ip.startsWith("fc") || ip.startsWith("fd") || ip.startsWith("fe8") || ip.startsWith("fe9") || ip.startsWith("fea") || ip.startsWith("feb");
  }
  return false;
}

const BLOCKED_HOSTS = new Set(["localhost", "metadata", "metadata.google.internal", "host.docker.internal", "internal"]);

export async function assertSafeUrl(raw: string): Promise<URL> {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new Error("Invalid URL");
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error("Only http and https URLs are allowed");
  const host = u.hostname.toLowerCase();
  if (BLOCKED_HOSTS.has(host) || host.endsWith(".internal") || host.endsWith(".local") || host.endsWith(".localhost") || isPrivateIp(host)) {
    throw new Error("Host is not allowed");
  }
  let records;
  try {
    records = await lookup(host, { all: true });
  } catch {
    throw new Error("Could not resolve host");
  }
  if (records.some((r) => isPrivateIp(r.address))) throw new Error("URL resolved to a private address");
  return u;
}

async function fetchLimited(
  initial: URL,
  timeoutMs = FETCH_TIMEOUT_MS,
): Promise<{
  url: string;
  status: number;
  headers: Record<string, string>;
  contentType: string;
  text: string;
  latencyMs: number;
  redirects: number;
  truncated: boolean;
}> {
  let url = initial;
  let redirects = 0;
  const started = Date.now();
  while (true) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(url, {
        signal: controller.signal,
        redirect: "manual",
        headers: { accept: "application/json, text/plain, */*" },
      });
      const location = response.headers.get("location");
      if (response.status >= 300 && response.status < 400 && location) {
        if (redirects++ >= MAX_REDIRECTS) throw new Error("Too many redirects");
        const next = await assertSafeUrl(new URL(location, url).toString());
        if (url.protocol === "https:" && next.protocol !== "https:") throw new Error("HTTPS downgrade redirect is not allowed");
        url = next;
        continue;
      }
      const headers: Record<string, string> = {};
      response.headers.forEach((value, key) => {
        if (["set-cookie", "content-encoding", "transfer-encoding"].includes(key)) return;
        headers[key] = value.length > 300 ? value.slice(0, 300) + "\u2026" : value;
      });
      const reader = response.body?.getReader();
      const chunks: Uint8Array[] = [];
      let size = 0;
      let truncated = false;
      if (reader) {
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          size += value.byteLength;
          if (size > MAX_BODY_BYTES) {
            truncated = true;
            await reader.cancel().catch(() => undefined);
            break;
          }
          chunks.push(value);
        }
      }
      return {
        url: url.toString(),
        status: response.status,
        headers,
        contentType: response.headers.get("content-type") || "",
        text: new TextDecoder().decode(Buffer.concat(chunks)),
        latencyMs: Date.now() - started,
        redirects,
        truncated,
      };
    } finally {
      clearTimeout(timer);
    }
  }
}

function parseJsonKeys(text: string, contentType: string): string[] {
  if (!contentType.includes("json") && !/^[\s]*[\[{]/.test(text)) return [];
  try {
    const value = JSON.parse(text);
    if (Array.isArray(value)) return ["[array]"];
    if (value && typeof value === "object") return Object.keys(value).slice(0, 40);
    return [];
  } catch {
    return [];
  }
}

export async function runEndpointAudit(args: { url: string }): Promise<ToolResult> {
  const fixes: string[] = [];
  let status: number | null = null;
  let headers: Record<string, string> = {};
  let bodyKeys: string[] = [];
  let mcpCard = false;
  let mcpCardStatus: number | null = null;
  let evidence: Record<string, unknown> = {};
  try {
    const target = await assertSafeUrl(args.url);
    const response = await fetchLimited(target);
    status = response.status;
    headers = response.headers;
    bodyKeys = parseJsonKeys(response.text, response.contentType);
    evidence = {
      finalUrl: response.url,
      latencyMs: response.latencyMs,
      redirects: response.redirects,
      bodyTruncated: response.truncated,
      contentType: response.contentType,
    };
    if (status === 401 || status === 403) {
      fixes.push(headers["www-authenticate"] ? `Auth required (${status})` : `Auth required (${status}) but no WWW-Authenticate header`);
    }
    if (status === 402 && !(headers["x402-accepts"] || headers["payment-required"])) {
      fixes.push("402 without payment discovery headers");
    }
    try {
      const cardRes = await fetchLimited(await assertSafeUrl(`${target.origin}/.well-known/mcp/server-card.json`), 5000);
      mcpCardStatus = cardRes.status;
      const parsedCard = JSON.parse(cardRes.text);
      mcpCard = cardRes.status >= 200 && cardRes.status < 300 && !!parsedCard && typeof parsedCard === "object";
    } catch {
      mcpCard = false;
    }
    if (!mcpCard && status !== 401 && status !== 403 && status !== 402) fixes.push("No valid /.well-known/mcp/server-card.json");
    if (!bodyKeys.length && response.contentType.includes("json") && status !== null && status >= 200 && status < 400) {
      fixes.push("JSON body is empty or invalid");
    }
    if (status !== null && status >= 500) fixes.push(`Server error ${status}`);
    else if (status !== null && status >= 400 && !fixes.length) fixes.push(`Client error ${status}`);
    if (!fixes.length) fixes.push("Endpoint looks healthy; MCP protocol probing is recommended");
  } catch (e) {
    fixes.push(
      e instanceof Error && e.name === "AbortError"
        ? `Request timed out after ${FETCH_TIMEOUT_MS}ms`
        : `Request failed: ${e instanceof Error ? e.message.slice(0, 160) : "unknown error"}`,
    );
  }
  let score = 0;
  if (status !== null && status >= 200 && status < 400) score += 30;
  if (mcpCard) score += 25;
  if (status === 402 && (headers["x402-accepts"] || headers["payment-required"])) score += 20;
  if (bodyKeys.length) score += 10;
  if (status !== null && status >= 500) score -= 15;
  score = Math.max(0, Math.min(100, score));
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(
          { url: args.url, status, headers, bodyKeys, mcpCard, mcpCardStatus, score, confidence: "low", evidence, fixes: fixes.slice(0, 5) },
          null,
          2,
        ),
      },
    ],
  };
}

function isAddress(value: string): boolean {
  return /^0x[0-9a-fA-F]{40}$/.test(value);
}

async function rpc<T>(method: string, params: unknown[]): Promise<T> {
  const r = await fetch(cfg.RPC_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    signal: AbortSignal.timeout(7000),
  });
  if (!r.ok) throw new Error("RPC unavailable");
  const body = (await r.json()) as { result?: T; error?: { message?: string } };
  if (body.error) throw new Error("RPC request failed");
  return body.result as T;
}

export async function runTokenRiskScan(args: { token: string }): Promise<ToolResult> {
  const token = (args.token || "").trim();
  const checks: Record<string, unknown> = {
    formatValid: isAddress(token),
    checksum: "not_verified",
    isContract: null,
    codeBytes: 0,
    nonce: null,
    chain: cfg.X402_NETWORK,
  };
  const warnings: string[] = [];
  let score = checks.formatValid ? 100 : 0;
  let risk: "low" | "medium" | "high" = checks.formatValid ? "low" : "high";
  if (!checks.formatValid) {
    warnings.push("Invalid Ethereum address format");
  } else {
    const lower = token.toLowerCase();
    try {
      const code = (await rpc<string>("eth_getCode", [lower, "latest"])) || "0x";
      const bytes = Math.max(0, (code.replace(/^0x/, "").length / 2) | 0);
      checks.isContract = bytes > 0;
      checks.codeBytes = bytes;
      if (!bytes) {
        warnings.push("No bytecode at address; this is not a token contract");
        risk = "high";
        score -= 50;
      } else {
        try {
          checks.nonce = parseInt(await rpc<string>("eth_getTransactionCount", [lower, "latest"]), 16);
        } catch {
          /* optional */
        }
      }
    } catch {
      warnings.push("On-chain lookup unavailable");
      risk = "medium";
      score -= 20;
    }
  }
  score = Math.max(0, Math.min(100, score));
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(
          {
            address: isAddress(token) ? token.toLowerCase() : token,
            label: "contract-address-snapshot",
            risk,
            score,
            checks,
            warnings,
            limitations: ["This is not a honeypot, liquidity, ownership, proxy, or malicious-code detector."],
          },
          null,
          2,
        ),
      },
    ],
  };
}

const toolCatalog = [
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
  if (kind === "test" && !TEST_ENDPOINTS) return json({ error: "test endpoints disabled" }, 404);
  const token = kind === "metrics" ? cfg.METRICS_TOKEN : cfg.TEST_ENDPOINT_TOKEN;
  if (kind === "metrics" && !token) return json({ error: "not found" }, 404);
  if (token && req.headers.get("authorization") !== `Bearer ${token}`) return json({ error: "unauthorized" }, 401);
  if (kind === "test" && !rateLimit(`test:${clientIp(req)}`, 20, 60_000)) return json({ error: "rate limited" }, 429);
  return null;
}

async function main() {
  const facilitator = new HTTPFacilitatorClient({ url: cfg.FACILITATOR_URL });
  const resource = new x402ResourceServer(facilitator);
  resource.register(cfg.X402_NETWORK, new ExactEvmScheme());
  await resource.initialize();
  const accepts = await resource.buildPaymentRequirements({
    scheme: "exact",
    network: cfg.X402_NETWORK,
    payTo: cfg.EVM_ADDRESS as `0x${string}`,
    price: cfg.X402_PRICE,
    extra: { name: ASSET, version: ASSET_VERSION },
  });

  serve(
    {
      fetch: async (req) => {
        const url = new URL(req.url);
        const path = url.pathname;
        if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
        if (path === "/" || path === "/test") {
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
            tools: toolCatalog.map((t) => t.alias).concat("ping"),
          });
        }
        if (path === "/metrics") {
          const denied = authorized(req, "metrics");
          return denied || json({ ...metrics, uptimeSec: Math.floor((Date.now() - Date.parse(metrics.startedAt)) / 1000) });
        }
        if (path === "/.well-known/mcp/server-card.json" || path === "/server-card.json") return json(card());
        if (path === "/test/x402") {
          const denied = authorized(req, "test");
          if (denied) return denied;
          metrics.testCalls++;
          return json({ network: cfg.X402_NETWORK, payTo: cfg.EVM_ADDRESS, price: cfg.X402_PRICE, accepts });
        }
        if (path === "/test/endpoint_audit" && req.method === "POST") {
          const denied = authorized(req, "test");
          if (denied) return denied;
          metrics.testCalls++;
          const body = (await req.json().catch(() => null)) as { url?: string } | null;
          if (!body?.url) return json({ error: "JSON body required: { url }" }, 400);
          const result = await runEndpointAudit({ url: body.url });
          const text = result.content[0] && "text" in result.content[0] ? String(result.content[0].text) : "{}";
          return json({ test: true, paid: false, result: JSON.parse(text) });
        }
        if (path === "/test/token_risk_scan" && req.method === "POST") {
          const denied = authorized(req, "test");
          if (denied) return denied;
          metrics.testCalls++;
          const body = (await req.json().catch(() => null)) as { token?: string } | null;
          if (!body?.token) return json({ error: "JSON body required: { token }" }, 400);
          const result = await runTokenRiskScan({ token: body.token });
          const text = result.content[0] && "text" in result.content[0] ? String(result.content[0].text) : "{}";
          return json({ test: true, paid: false, result: JSON.parse(text) });
        }
        if (path === "/mcp") {
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
            return new Response(response.body, { status: response.status, headers });
          } catch {
            metrics.mcpErrors++;
            return json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal MCP error" }, id: null }, 500);
          }
        }
        return new Response("not found", { status: 404, headers: CORS });
      },
      port: cfg.PORT,
    },
    () => console.log(`${SERVER_NAME} v${SERVER_VERSION} on :${cfg.PORT}`),
  );
}

if (process.env.NODE_ENV !== "test") {
  main().catch((error) => {
    console.error("Fatal startup error", error instanceof Error ? error.message : error);
    process.exit(1);
  });
}
