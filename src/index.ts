/**
 * @motikolorado/ai-tools — paid MCP tool library
 * One server, many tools behind aliases. Shared payment, transport, response shape.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { serve } from "@hono/node-server";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { createPaymentWrapper, x402ResourceServer } from "@x402/mcp";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { z } from "zod";
import type { PaymentWrappedHandler, ToolResult } from "@x402/mcp";

// ---- shared config ----
const EVM_ADDRESS = process.env.EVM_ADDRESS as `0x${string}`;
if (!EVM_ADDRESS || !EVM_ADDRESS.startsWith("0x")) {
  console.error("EVM_ADDRESS required (0x... address on Base Sepolia)");
  process.exit(1);
}
const FACILITATOR_URL = process.env.FACILITATOR_URL;
if (!FACILITATOR_URL) {
  console.error("FACILITATOR_URL required");
  process.exit(1);
}
const PORT = parseInt(process.env.PORT || "8080", 10);
const SERVER_NAME = "ai-tools";
const SERVER_VERSION = "1.0.0";
const NETWORK = "eip155:84532";
const PRICE = "$0.02";
const ASSET = "USDC";
const ASSET_VERSION = "2";

// ---- shared x402 scaffolding ----
async function initX402() {
  const facilitatorClient = new HTTPFacilitatorClient({ url: FACILITATOR_URL });
  const resourceServer = new x402ResourceServer(facilitatorClient);
  resourceServer.register(NETWORK, new ExactEvmScheme());
  await resourceServer.initialize();
  return { facilitatorClient, resourceServer };
}

// ---- tool registry ----
type ToolDef = {
  alias: string;
  name: string;
  description: string;
  schema: Record<string, unknown>;
  handler: (args: Record<string, unknown>) => Promise<{ content: Array<{ type: string; text: string }> }>;
};

const tools: ToolDef[] = [];

// ---- tool implementations (moved from existing servers) ----

async function runEndpointAudit(args: { url: string }) {
  const url = args.url as string;
  const fixes: string[] = [];
  let status: number | null = null;
  const headers: Record<string, string> = {};
  let bodyKeys: string[] = [];
  let mcpCard = false;
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const r = await fetch(url, { signal: controller.signal, redirect: "follow" });
    clearTimeout(timeout);
    status = r.status;
    r.headers.forEach((value, key) => {
      const k = key.toLowerCase();
      if (k !== "transfer-encoding" && k !== "content-encoding") {
        headers[k] = value;
      }
    });
    const contentType = r.headers.get("content-type") || "";
    if (contentType.includes("application/json")) {
      try {
        const body = await r.json();
        if (body && typeof body === "object") {
          bodyKeys = Object.keys(body);
        }
      } catch {}
    }
    if (status === 401 || status === 403) {
      const authHeader = r.headers.get("www-authenticate") || "";
      if (authHeader) {
        fixes.push("Missing or misconfigured auth — server returns " + status + " with WWW-Authenticate: " + authHeader.slice(0, 80));
      } else {
        fixes.push("Auth is required but no WWW-Authenticate header present — clients cannot discover how to authenticate");
      }
    }
    if (status === 402) {
      const acceptHeader = r.headers.get("x402-accepts") || "";
      if (acceptHeader) {
        fixes.push("Server is x402-ready but paid tool schema may be incomplete — confirm /.well-known/mcp/server-card.json or MCP discovery");
      } else {
        fixes.push("Server returns 402 but lacks x402-accepts header — clients cannot discover payment requirements");
      }
    }
    if (url.endsWith("/mcp") || url.includes("/.well-known/mcp")) {
      try {
        const card = await r.json();
        if (card && typeof card === "object") mcpCard = true;
      } catch {}
    }
    if (!mcpCard && status !== 402 && status !== 401 && status !== 403) {
      fixes.push("No /.well-known/mcp/server-card.json detected — consider adding it so scanners can discover your server");
    }
    if (bodyKeys.length === 0 && contentType.includes("application/json") && status !== null && status >= 200 && status < 400) {
      fixes.push("JSON body is empty or not an object — confirm the endpoint returns structured data agents can parse");
    }
    if (status !== null && status >= 400 && status < 500 && fixes.length === 0) {
      fixes.push("Client error " + status + " — check request format, auth, and path");
    }
    if (status !== null && status >= 500) {
      fixes.push("Server error " + status + " — check upstream health and logs");
    }
    if (fixes.length === 0 && status !== null && status >= 200 && status < 400 && mcpCard) {
      fixes.push("Endpoint looks healthy and x402-ready — no urgent fixes");
    }
    if (fixes.length === 0 && status !== null && status >= 200 && status < 400 && !mcpCard) {
      fixes.push("Endpoint responds but has no /.well-known/mcp/server-card.json — add one so scanners can discover it");
    }
  } catch (err: unknown) {
    status = null;
    if (err && typeof err === "object" && "name" in err && err.name === "AbortError") {
      fixes.push("Request timed out after 8s — consider increasing timeout or checking upstream latency");
    } else if (err && typeof err === "object" && "message" in err && typeof err.message === "string") {
      fixes.push("Request failed: " + err.message.slice(0, 160));
    } else {
      fixes.push("Request failed: unknown error");
    }
  }
  let score = 0;
  if (status !== null && status >= 200 && status < 400) score += 30;
  if (mcpCard) score += 25;
  if (status === 402 && headers["x402-accepts"]) score += 20;
  if (status === 401 || status === 403) score += 10;
  if (bodyKeys.length > 0) score += 10;
  if (status !== null && status >= 500) score -= 15;
  score = Math.max(0, Math.min(100, score));
  const content: Array<{ type: "text"; text: string }> = [];
  content.push({ type: "text" as const, text: JSON.stringify({ url, status, headers, bodyKeys, mcpCard, score, fixes }, null, 2) });
  const RESULT: ToolResult = { content };
  return RESULT;
}

async function runTokenRiskScan(args: { token: string }) {
  const token = args.token as string;
  const warnings: string[] = [];
  let risk: "low" | "medium" | "high" | "critical" = "low";
  let score = 100;
  const usdc = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
  if (token.toLowerCase() === usdc.toLowerCase()) {
    warnings.push("Token address matches USDC on Base Sepolia (confirm chain)");
  }
  if (token.length !== 42 || !token.startsWith("0x")) {
    risk = "high";
    score = 35;
    warnings.push("Invalid Ethereum address format");
    const c: Array<{ type: "text"; text: string }> = [];
    c.push({
      type: "text" as const,
      text: JSON.stringify({
        address: token,
        label: "INVALID",
        risk: risk,
        score: score,
        checks: { formatValid: false } as const,
        warnings: warnings,
      }, null, 2),
    });
    return { content: c };
  }
  const checksum = token.toLowerCase() === token ? "no" : "yes";
  if (checksum === "no") {
    warnings.push("Address is not checksummed — may indicate copy/paste risk");
    score -= 5;
  }
  const okC: Array<{ type: "text"; text: string }> = [];
  okC.push({
    type: "text" as const,
    text: JSON.stringify({
      address: token.toLowerCase(),
      label: token.slice(0, 10) + "...",
      risk: risk,
      score: score,
      checks: { formatValid: true, checksummed: checksum, chain: NETWORK } as const,
      warnings: warnings,
    }, null, 2),
  });
  const RESULT: ToolResult = { content: okC };
  return RESULT;
}
// ---- register tools ----

tools.push({
  alias: "endpoint_audit",
  name: "endpoint_audit",
  description:
    "Audit a live URL and return a 0-100 health + x402-readiness score with up to 5 concrete fixes. Purpose: let agents verify an HTTP endpoint before trusting or paying it. Usage: pass a single url (http/https); the tool fetches it (follow redirects, 8s timeout) and inspects status, response headers, whether the body is JSON with keys, and whether /.well-known/mcp/server-card.json exists. It also flags 401/403 auth gaps, 402 x402-accepts presence, and 4xx/5xx issues. Response: a JSON object with url, status, headers, bodyKeys, mcpCard (bool), score (0-100), and fixes (array of strings, up to 5). Price: $0.02 on Base Sepolia via x402.",
  schema: { url: { type: "string", description: "URL to audit (http or https)" } },
  handler: runEndpointAudit as (args: unknown) => Promise<{ content: Array<{ type: "text"; text: string }> }>,
});

tools.push({
  alias: "token_risk_scan",
  name: "token_risk_scan",
  description:
    "Scan an Ethereum token address for common risk signals and return a risk level (low/medium/high/critical), a 0-100 score, per-check details, and warnings. Purpose: let agents vet a token before interacting with or trusting it. Usage: pass a single token address (0x-prefixed 42-char Ethereum address); the tool validates the format and checksum, compares it to the known USDC address on Base Sepolia, and reports formatValid, checksummed (yes/no), chain, and any warnings. Response: a JSON object with address, label (truncated address), risk, score (0-100), checks (object with formatValid and checksummed), and warnings (array of strings). If the address is missing or malformed, the tool returns label 'INVALID' with risk 'high' and score 35 rather than a generic error. Price: $0.02 on Base Sepolia via x402.",
  schema: { token: { type: "string", description: "Ethereum token contract address to scan (e.g. 0x...)" } },
  handler: runTokenRiskScan as (args: unknown) => Promise<{ content: Array<{ type: "text"; text: string }> }>,
});

// ---- build server ----
async function main() {
  console.log(`\n${SERVER_NAME} MCP server (x402-paid, streamable HTTP, Smithery-compatible)\n`);

  const { facilitatorClient, resourceServer } = await initX402();

  const mcpServer = new McpServer({
    name: SERVER_NAME,
    version: SERVER_VERSION,
  });

  function paidTool(accepts: Awaited<ReturnType<typeof resourceServer.buildPaymentRequirements>>) {
    return createPaymentWrapper(resourceServer, { accepts });
  }

  function buildAccepts(): ReturnType<typeof resourceServer.buildPaymentRequirements> {
    return resourceServer.buildPaymentRequirements({
      scheme: "exact",
      network: NETWORK,
      payTo: EVM_ADDRESS,
      price: PRICE,
      extra: { name: ASSET, version: ASSET_VERSION },
    });
  }

  // ---- register tools (inside main, after x402 init) ----
  for (const tool of tools) {
    const toolAccepts = await buildAccepts();
    const paidWrapper = paidTool(toolAccepts);
    const argName = Object.keys(tool.schema)[0];
    const argSchema = tool.schema[argName] as { type: string; description?: string };

    let zSchema: z.ZodTypeAny;
    if (argSchema.type === "string") {
      zSchema = z.string();
    } else {
      zSchema = z.any();
    }

    const wrapped: PaymentWrappedHandler<Record<string, unknown>> = async (args: Record<string, unknown>, _context: any) => {
      return tool.handler(args) as unknown as ToolResult;
    };
    mcpServer.tool(
      tool.alias,
      tool.description,
      { [argName]: zSchema },
      paidWrapper(wrapped),
    );
  }

  // ---- free health (ping excluded from paid accepts) ----
  mcpServer.tool("ping", "Free health check", {}, async () => {
    return { content: [{ type: "text" as const, text: "pong" }] };
  });

  const serverCard = {
    name: SERVER_NAME,
    description:
      "Multi-tool paid MCP server: endpoint_audit + token_risk_scan behind aliases. Agents call one tool per request; payment is per-call via x402 (USDC on Base Sepolia, $0.02). endpoint_audit audits a URL (status, headers, JSON body, MCP card presence) and returns a 0-100 score with up to 5 fixes. token_risk_scan validates an Ethereum token address (format, checksum, USDC match) and returns a risk level, 0-100 score, per-check details, and warnings. Deployed at https://rado-ai-tools.fly.dev.",
    repository: "https://github.com/motikolorado/ai-tools",
    homepage: "https://rado-ai-tools.fly.dev",
    version: SERVER_VERSION,
    license: "MIT",
    pricing: {
      model: "pay-per-call",
      currency: "USDC",
      pricePerCall: "0.02",
      network: "eip155:84532",
      currencyContract: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    },
    tools: tools.map((t) => ({
      name: t.alias,
      description: t.description,
    })),
  };

  const app = serve({
    fetch: async (req: Request) => {
      if (req.url.endsWith("/.well-known/mcp/server-card.json")) {
        return new Response(JSON.stringify(serverCard), {
          headers: { "content-type": "application/json" },
        });
      }
      if (req.url.endsWith("/health")) {
        const healthTools: string[] = [];
        for (const t of tools) {
          healthTools.push(`${t.alias} (paid: ${PRICE})`);
        }
        return new Response(
          JSON.stringify({
            status: "ok",
            tools: healthTools,
            version: SERVER_VERSION,
          }),
          { headers: { "content-type": "application/json" } },
        );
      }
      if (req.url.endsWith("/mcp") || req.url.endsWith("/messages")) {
        try {
          const transport = new WebStandardStreamableHTTPServerTransport({
            sessionIdGenerator: undefined,
          });
          return await transport.handleRequest(req);
        } catch (err: unknown) {
          console.error("transport.handleRequest error:", err);
          let msg: string;
          if (typeof err === "string") {
            msg = err;
          } else if (err && typeof err === "object" && "message" in err) {
            msg = String((err as { message?: unknown }).message ?? "");
          } else {
            msg = String(err);
          }
          return new Response(msg, {
            status: 500,
            headers: { "content-type": "text/plain" },
          });
        }
      }
      return new Response("not found", { status: 404 });
    },
    port: PORT,
  }, () => {
    console.log(`${SERVER_NAME} listening on http://localhost:${PORT}`);

    for (const t of tools) {
      const key = Object.keys(t.schema)[0];
      console.log(`  Paid: ${t.alias} (${key}) — ${PRICE}`);
    }

    console.log(`  Free: ping`);
    console.log(`  MCP Streamable HTTP: http://localhost:${PORT}/mcp`);
    console.log(`  Health: http://localhost:${PORT}/health`);
    console.log(`  Server card: http://localhost:${PORT}/.well-known/mcp/server-card.json`);
  });
}

main().catch((e) => {
  console.error("Fatal:", e);
  process.exit(1);
});



