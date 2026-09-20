/**
 * @motikolorado/ai-tools — paid MCP tool library
 * Streamable HTTP + x402. One McpServer per request (SDK 1:1 bind).
 */
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

const EVM_ADDRESS = process.env.EVM_ADDRESS as `0x${string}`;
if (!EVM_ADDRESS || !EVM_ADDRESS.startsWith("0x")) {
  console.error("EVM_ADDRESS required (0x... payTo address)");
  process.exit(1);
}
const FACILITATOR_URL = process.env.FACILITATOR_URL;
if (!FACILITATOR_URL) {
  console.error("FACILITATOR_URL required");
  process.exit(1);
}

const PORT = parseInt(process.env.PORT || "8080", 10);
const SERVER_NAME = "ai-tools";
const SERVER_VERSION = "1.1.0";
const NETWORK = process.env.X402_NETWORK || "eip155:84532";
const PRICE = process.env.X402_PRICE || "$0.02";
const ASSET = "USDC";
const ASSET_VERSION = "2";
const PUBLIC_URL = (process.env.PUBLIC_URL || "https://rado-ai-tools.fly.dev").replace(/\/$/, "");
const RPC_URL = process.env.RPC_URL || "https://sepolia.base.org";
const FETCH_TIMEOUT_MS = 8000;
const MAX_BODY_BYTES = 64 * 1024;
const IS_TESTNET = NETWORK.includes("84532") || NETWORK.includes("sepolia");
const TEST_ENDPOINTS =
  (process.env.ENABLE_TEST_ENDPOINTS ?? (IS_TESTNET ? "true" : "false")) === "true";
const TEST_TOKEN = process.env.TEST_ENDPOINT_TOKEN || "";
const USDC_SEPOLIA = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";

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
  return (
    req.headers.get("fly-client-ip") ||
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    "unknown"
  );
}

function rateLimit(key: string, max: number, windowMs: number): boolean {
  const now = Date.now();
  const b = rateBuckets.get(key);
  if (!b || now - b.t > windowMs) {
    rateBuckets.set(key, { n: 1, t: now });
    return true;
  }
  if (b.n >= max) return false;
  b.n += 1;
  return true;
}

function isPrivateIp(ip: string): boolean {
  const v = ip.replace(/^\[|\]$/g, "");
  if (v === "::1" || v.startsWith("fc") || v.startsWith("fd") || v.startsWith("fe80")) return true;
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(v);
  if (!m) return false;
  const a = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])];
  if (a[0] === 10 || a[0] === 127 || a[0] === 0) return true;
  if (a[0] === 169 && a[1] === 254) return true;
  if (a[0] === 172 && a[1] >= 16 && a[1] <= 31) return true;
  if (a[0] === 192 && a[1] === 168) return true;
  if (a[0] === 100 && a[1] >= 64 && a[1] <= 127) return true;
  return false;
}

const BLOCKED_HOSTS = new Set(["localhost", "metadata.google.internal", "metadata", "internal"]);

async function assertSafeUrl(raw: string): Promise<URL> {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new Error("Invalid URL");
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    throw new Error("Only http and https URLs are allowed");
  }
  const host = u.hostname.toLowerCase();
  if (BLOCKED_HOSTS.has(host) || host.endsWith(".internal") || host.endsWith(".local") || host.endsWith(".localhost")) {
    throw new Error("Host is not allowed");
  }
  if (isIP(host) && isPrivateIp(host)) {
    throw new Error("Private or link-local IP is not allowed");
  }
  try {
    const recs = await lookup(host, { all: true });
    for (const r of recs) {
      if (isPrivateIp(r.address)) throw new Error("URL resolved to a private address");
    }
  } catch (e) {
    if (e instanceof Error && e.message.includes("private")) throw e;
    throw new Error("Could not resolve host");
  }
  return u;
}

async function fetchLimited(url: string, timeoutMs = FETCH_TIMEOUT_MS): Promise<{
  status: number;
  headers: Record<string, string>;
  contentType: string;
  text: string;
}> {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const r = await fetch(url, {
      signal: controller.signal,
      redirect: "follow",
      headers: { accept: "application/json, text/plain, */*" },
    });
    const headers: Record<string, string> = {};
    r.headers.forEach((value, key) => {
      const k = key.toLowerCase();
      if (k === "transfer-encoding" || k === "content-encoding" || k === "set-cookie") return;
      headers[k] = value.length > 300 ? value.slice(0, 300) + "…" : value;
    });
    const contentType = r.headers.get("content-type") || "";
    const reader = r.body?.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    if (reader) {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > MAX_BODY_BYTES) {
          try { await reader.cancel(); } catch { /* ignore */ }
          break;
        }
        chunks.push(value);
      }
    }
    const text = new TextDecoder().decode(Buffer.concat(chunks));
    return { status: r.status, headers, contentType, text };
  } finally {
    clearTimeout(t);
  }
}

function parseJsonKeys(text: string, contentType: string): string[] {
  if (!contentType.includes("application/json") && !text.trim().startsWith("{") && !text.trim().startsWith("[")) {
    return [];
  }
  try {
    const body = JSON.parse(text);
    if (body && typeof body === "object" && !Array.isArray(body)) return Object.keys(body).slice(0, 40);
    if (Array.isArray(body)) return ["[array]"];
  } catch { /* ignore */ }
  return [];
}

export async function runEndpointAudit(args: { url: string }) {
  const fixes: string[] = [];
  let status: number | null = null;
  let headers: Record<string, string> = {};
  let bodyKeys: string[] = [];
  let mcpCard = false;
  let mcpCardStatus: number | null = null;
  try {
    const u = await assertSafeUrl(args.url);
    const r = await fetchLimited(u.toString());
    status = r.status;
    headers = r.headers;
    bodyKeys = parseJsonKeys(r.text, r.contentType);
    if (status === 401 || status === 403) {
      const authHeader = r.headers["www-authenticate"] || "";
      fixes.push(authHeader
        ? `Auth required (${status}) WWW-Authenticate: ${authHeader.slice(0, 80)}`
        : `Auth required (${status}) but no WWW-Authenticate header`);
    }
    if (status === 402) {
      const acceptHeader = r.headers["x402-accepts"] || r.headers["payment-required"] || "";
      fixes.push(acceptHeader
        ? "402 with payment discovery header present"
        : "402 without x402-accepts / PAYMENT-REQUIRED");
    }
    const cardUrl = `${u.origin}/.well-known/mcp/server-card.json`;
    try {
      await assertSafeUrl(cardUrl);
      const card = await fetchLimited(cardUrl, 5000);
      mcpCardStatus = card.status;
      if (card.status >= 200 && card.status < 300) {
        const parsed = JSON.parse(card.text);
        if (parsed && typeof parsed === "object") mcpCard = true;
      }
    } catch {
      mcpCard = false;
    }
    if (!mcpCard && status !== 402 && status !== 401 && status !== 403) {
      fixes.push("No /.well-known/mcp/server-card.json");
    }
    if (bodyKeys.length === 0 && r.contentType.includes("application/json") && status !== null && status >= 200 && status < 400) {
      fixes.push("JSON body is empty or not an object");
    }
    if (status !== null && status >= 400 && status < 500 && fixes.length === 0) {
      fixes.push(`Client error ${status}`);
    }
    if (status !== null && status >= 500) {
      fixes.push(`Server error ${status}`);
    }
    if (fixes.length === 0 && status !== null && status >= 200 && status < 400 && mcpCard) {
      fixes.push("Endpoint looks healthy and MCP-discoverable");
    }
  } catch (err: unknown) {
    status = null;
    if (err && typeof err === "object" && "name" in err && (err as { name: string }).name === "AbortError") {
      fixes.push("Request timed out after 8s");
    } else if (err instanceof Error) {
      fixes.push("Request failed: " + err.message.slice(0, 160));
    } else {
      fixes.push("Request failed: unknown error");
    }
  }
  let score = 0;
  if (status !== null && status >= 200 && status < 400) score += 30;
  if (mcpCard) score += 25;
  if (status === 402 && (headers["x402-accepts"] || headers["payment-required"])) score += 20;
  if (status === 401 || status === 403) score += 10;
  if (bodyKeys.length > 0) score += 10;
  if (status !== null && status >= 500) score -= 15;
  score = Math.max(0, Math.min(100, score));
  const RESULT: ToolResult = {
    content: [{ type: "text", text: JSON.stringify({ url: args.url, status, headers, bodyKeys, mcpCard, mcpCardStatus, score, fixes: fixes.slice(0, 5) }, null, 2) }],
  };
  return RESULT;
}

function isAddress(token: string): boolean {
  return /^0x[0-9a-fA-F]{40}$/.test(token);
}

async function rpc<T>(method: string, params: unknown[]): Promise<T> {
  const r = await fetch(RPC_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    signal: AbortSignal.timeout(7000),
  });
  if (!r.ok) throw new Error(`RPC HTTP ${r.status}`);
  const body = (await r.json()) as { result?: T; error?: { message?: string } };
  if (body.error) throw new Error(body.error.message || "RPC error");
  return body.result as T;
}

export async function runTokenRiskScan(args: { token: string }) {
  const token = (args.token || "").trim();
  const warnings: string[] = [];
  let risk: "low" | "medium" | "high" | "critical" = "low";
  let score = 100;
  const checks: Record<string, unknown> = {
    formatValid: false, checksummed: "unknown", isContract: null, codeBytes: 0, nonce: null, chain: NETWORK, rpc: RPC_URL,
  };
  if (!isAddress(token)) {
    const RESULT: ToolResult = {
      content: [{ type: "text", text: JSON.stringify({ address: token, label: "INVALID", risk: "high", score: 35, checks: { ...checks, formatValid: false }, warnings: ["Invalid Ethereum address format"] }, null, 2) }],
    };
    return RESULT;
  }
  checks.formatValid = true;
  const lower = token.toLowerCase();
  const mixed = token !== lower && token !== token.toUpperCase();
  checks.checksummed = mixed ? "yes" : "no";
  if (!mixed) { warnings.push("Address is not mixed-case checksummed"); score -= 5; }
  if (lower === USDC_SEPOLIA.toLowerCase()) warnings.push("Matches USDC on Base Sepolia");
  if (lower === USDC_BASE.toLowerCase()) warnings.push("Matches USDC on Base mainnet");
  const known = lower === USDC_SEPOLIA.toLowerCase() || lower === USDC_BASE.toLowerCase();
  try {
    const code = await rpc<string>("eth_getCode", [lower, "latest"]);
    const hex = (code || "0x").replace(/^0x/, "");
    const isContract = hex.length > 0;
    checks.isContract = isContract;
    checks.codeBytes = Math.floor(hex.length / 2);
    if (!isContract) { warnings.push("No bytecode at address — not an ERC-20"); risk = "high"; score -= 40; }
    else if ((checks.codeBytes as number) < 100) { warnings.push("Very small bytecode"); risk = "medium"; score -= 15; }
    try { checks.nonce = parseInt(await rpc<string>("eth_getTransactionCount", [lower, "latest"]), 16); } catch { checks.nonce = null; }
  } catch (err) {
    warnings.push("On-chain lookup failed: " + (err instanceof Error ? err.message : "rpc error"));
    if (risk === "low") risk = "medium";
    score -= 20;
  }
  if (known && checks.isContract) { risk = "low"; score = Math.max(score, 80); }
  if (score <= 40) risk = risk === "critical" ? risk : "high";
  else if (score <= 65 && risk === "low") risk = "medium";
  score = Math.max(0, Math.min(100, score));
  const RESULT: ToolResult = {
    content: [{ type: "text", text: JSON.stringify({ address: lower, label: token.slice(0, 10) + "…", risk, score, checks, warnings }, null, 2) }],
  };
  return RESULT;
}

const toolCatalog = [
  {
    alias: "endpoint_audit",
    description: "Audit a live URL and return a 0-100 health + MCP/x402-readiness score with up to 5 fixes. SSRF-blocked. Price: $0.02 USDC via x402.",
    schema: { url: z.string().min(8).describe("HTTP or HTTPS URL to audit") },
    inputSchema: { type: "object", properties: { url: { type: "string", description: "HTTP or HTTPS URL to audit" } }, required: ["url"] },
    example: { url: "https://rado-ai-tools.fly.dev/health" },
    handler: async (args: Record<string, unknown>) => runEndpointAudit({ url: String(args.url || "") }),
  },
  {
    alias: "token_risk_scan",
    description: "Scan an Ethereum address on the configured chain: format, checksum, eth_getCode, nonce. Not a honeypot detector. Price: $0.02 USDC via x402.",
    schema: { token: z.string().min(4).describe("0x-prefixed token or contract address") },
    inputSchema: { type: "object", properties: { token: { type: "string", description: "0x-prefixed address" } }, required: ["token"] },
    example: { token: USDC_SEPOLIA },
    handler: async (args: Record<string, unknown>) => runTokenRiskScan({ token: String(args.token || "") }),
  },
];

function bazaarExtension(toolName: string, description: string, inputSchema: unknown, example: unknown) {
  return {
    bazaar: {
      info: { type: "mcp", toolName, description, transport: "streamable-http", url: `${PUBLIC_URL}/mcp` },
      schema: { inputSchema, example },
    },
  };
}

function serverCard() {
  return {
    name: SERVER_NAME,
    description: "Paid MCP tools: endpoint_audit + token_risk_scan. x402 USDC per call. Streamable HTTP at /mcp.",
    repository: "https://github.com/motikolorado/ai-tools",
    homepage: PUBLIC_URL,
    version: SERVER_VERSION,
    license: "MIT",
    pricing: {
      model: "pay-per-call",
      currency: ASSET,
      pricePerCall: PRICE.replace("$", ""),
      network: NETWORK,
      currencyContract: IS_TESTNET ? USDC_SEPOLIA : USDC_BASE,
    },
    tools: toolCatalog.map((t) => ({ name: t.alias, description: t.description, pricePerCall: PRICE.replace("$", "") })),
  };
}

type ResourceServer = InstanceType<typeof x402ResourceServer>;

function buildMcpServer(
  resourceServer: ResourceServer,
  accepts: Awaited<ReturnType<ResourceServer["buildPaymentRequirements"]>>,
): McpServer {
  const mcpServer = new McpServer({ name: SERVER_NAME, version: SERVER_VERSION });
  for (const tool of toolCatalog) {
    const paid = createPaymentWrapper(resourceServer, {
      accepts,
      resource: { url: `mcp://tool/${tool.alias}`, description: tool.description },
      extensions: bazaarExtension(tool.alias, tool.description, tool.inputSchema, tool.example),
    } as Parameters<typeof createPaymentWrapper>[1]);
    const wrapped: PaymentWrappedHandler<Record<string, unknown>> = async (args) => {
      metrics.toolCalls += 1;
      try {
        return (await tool.handler(args)) as unknown as ToolResult;
      } catch (e) {
        metrics.toolErrors += 1;
        throw e;
      }
    };
    mcpServer.tool(tool.alias, tool.description, tool.schema, paid(wrapped));
  }
  mcpServer.tool("ping", "Free health check", {}, async () => ({
    content: [{ type: "text" as const, text: "pong" }],
  }));
  return mcpServer;
}

function authorizeTest(req: Request): Response | null {
  if (!TEST_ENDPOINTS) return json({ error: "test endpoints disabled" }, 404);
  if (TEST_TOKEN) {
    const auth = req.headers.get("authorization") || "";
    if (auth !== `Bearer ${TEST_TOKEN}`) return json({ error: "unauthorized" }, 401);
  }
  if (!rateLimit(`test:${clientIp(req)}`, 30, 60_000)) return json({ error: "rate limited" }, 429);
  return null;
}

async function handleMcp(
  req: Request,
  resourceServer: ResourceServer,
  accepts: Awaited<ReturnType<ResourceServer["buildPaymentRequirements"]>>,
): Promise<Response> {
  metrics.mcpRequests += 1;
  const mcpServer = buildMcpServer(resourceServer, accepts);
  const transport = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  await mcpServer.connect(transport);
  try {
    const res = await transport.handleRequest(req);
    const headers = new Headers(res.headers);
    for (const [k, v] of Object.entries(CORS)) {
      if (!headers.has(k)) headers.set(k, v);
    }
    return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
  } catch (err) {
    metrics.mcpErrors += 1;
    const msg = err instanceof Error ? err.message : String(err);
    console.error("mcp handleRequest:", msg);
    return json({ jsonrpc: "2.0", error: { code: -32603, message: msg }, id: null }, 500);
  }
}

async function main() {
  const facilitatorClient = new HTTPFacilitatorClient({ url: FACILITATOR_URL });
  const resourceServer = new x402ResourceServer(facilitatorClient);
  resourceServer.register(NETWORK, new ExactEvmScheme());
  await resourceServer.initialize();
  const accepts = await resourceServer.buildPaymentRequirements({
    scheme: "exact",
    network: NETWORK,
    payTo: EVM_ADDRESS,
    price: PRICE,
    extra: { name: ASSET, version: ASSET_VERSION },
  });
  serve({
    fetch: async (req: Request) => {
      const url = new URL(req.url);
      const path = url.pathname;
      if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
      if (path === "/" || path === "/test") {
        return json({
          name: SERVER_NAME,
          version: SERVER_VERSION,
          network: NETWORK,
          price: PRICE,
          mcp: `${PUBLIC_URL}/mcp`,
          health: `${PUBLIC_URL}/health`,
          card: `${PUBLIC_URL}/.well-known/mcp/server-card.json`,
          metrics: `${PUBLIC_URL}/metrics`,
          testnet: IS_TESTNET,
          testEndpoints: TEST_ENDPOINTS ? {
            x402: "GET /test/x402",
            audit: "POST /test/endpoint_audit {\"url\":\"https://...\"}",
            token: "POST /test/token_risk_scan {\"token\":\"0x...\"}",
            note: "Test routes run tool logic without x402. Disabled on mainnet unless ENABLE_TEST_ENDPOINTS=true.",
          } : null,
        });
      }
      if (path === "/health") {
        return json({
          status: "ok",
          tools: toolCatalog.map((t) => `${t.alias} (paid: ${PRICE})`).concat(["ping (free)"]),
          version: SERVER_VERSION,
          network: NETWORK,
        });
      }
      if (path === "/metrics") {
        return json({ ...metrics, uptimeSec: Math.floor((Date.now() - Date.parse(metrics.startedAt)) / 1000) });
      }
      if (path === "/.well-known/mcp/server-card.json" || path === "/server-card.json") {
        return json(serverCard());
      }
      if (path === "/test/x402") {
        const denied = authorizeTest(req);
        if (denied) return denied;
        metrics.testCalls += 1;
        return json({
          network: NETWORK,
          payTo: EVM_ADDRESS,
          price: PRICE,
          asset: ASSET,
          facilitator: FACILITATOR_URL,
          accepts,
          howTo: [
            "POST /mcp initialize (free)",
            "tools/list (free)",
            "tools/call without payment → PaymentRequired",
            "Retry with x402 payment on Base Sepolia USDC",
            "Or POST /test/* with no payment",
          ],
        });
      }
      if (path === "/test/endpoint_audit" && req.method === "POST") {
        const denied = authorizeTest(req);
        if (denied) return denied;
        metrics.testCalls += 1;
        let body: { url?: string } = {};
        try { body = (await req.json()) as { url?: string }; } catch { return json({ error: "JSON body required: { url }" }, 400); }
        if (!body.url) return json({ error: "url required" }, 400);
        const result = await runEndpointAudit({ url: body.url });
        const text = result.content[0] && "text" in result.content[0] ? String(result.content[0].text) : "{}";
        return json({ test: true, paid: false, result: JSON.parse(text) });
      }
      if (path === "/test/token_risk_scan" && req.method === "POST") {
        const denied = authorizeTest(req);
        if (denied) return denied;
        metrics.testCalls += 1;
        let body: { token?: string } = {};
        try { body = (await req.json()) as { token?: string }; } catch { return json({ error: "JSON body required: { token }" }, 400); }
        if (!body.token) return json({ error: "token required" }, 400);
        const result = await runTokenRiskScan({ token: body.token });
        const text = result.content[0] && "text" in result.content[0] ? String(result.content[0].text) : "{}";
        return json({ test: true, paid: false, result: JSON.parse(text) });
      }
      if (path === "/mcp" || path === "/messages") {
        if (!rateLimit(`mcp:${clientIp(req)}`, 120, 60_000)) {
          return json({ jsonrpc: "2.0", error: { code: -32000, message: "rate limited" }, id: null }, 429);
        }
        return handleMcp(req, resourceServer, accepts);
      }
      return new Response("not found", { status: 404, headers: CORS });
    },
    port: PORT,
  }, () => {
    console.log(`${SERVER_NAME} v${SERVER_VERSION} on :${PORT}`);
    console.log(`  MCP: ${PUBLIC_URL}/mcp`);
    console.log(`  Test endpoints: ${TEST_ENDPOINTS ? "on" : "off"}`);
  });
}

main().catch((e) => {
  console.error("Fatal:", e);
  process.exit(1);
});
