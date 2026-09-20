import type { ToolResult } from "@x402/mcp";
import { assertSafeUrl, fetchLimited, FETCH_TIMEOUT_MS, parseJsonKeys } from "./ssrf.js";

export type ToolRuntime = {
  rpcUrl: string;
  network: string;
};

function isAddress(value: string): boolean {
  return /^0x[0-9a-fA-F]{40}$/.test(value);
}

async function rpc<T>(rpcUrl: string, method: string, params: unknown[]): Promise<T> {
  const r = await fetch(rpcUrl, {
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

export async function runTokenRiskScan(args: { token: string }, runtime: ToolRuntime): Promise<ToolResult> {
  const token = (args.token || "").trim();
  const checks: Record<string, unknown> = {
    formatValid: isAddress(token),
    checksum: "not_verified",
    isContract: null,
    codeBytes: 0,
    nonce: null,
    chain: runtime.network,
  };
  const warnings: string[] = [];
  let score = checks.formatValid ? 100 : 0;
  let risk: "low" | "medium" | "high" = checks.formatValid ? "low" : "high";
  if (!checks.formatValid) {
    warnings.push("Invalid Ethereum address format");
  } else {
    const lower = token.toLowerCase();
    try {
      const code = (await rpc<string>(runtime.rpcUrl, "eth_getCode", [lower, "latest"])) || "0x";
      const bytes = Math.max(0, (code.replace(/^0x/, "").length / 2) | 0);
      checks.isContract = bytes > 0;
      checks.codeBytes = bytes;
      if (!bytes) {
        warnings.push("No bytecode at address; this is not a token contract");
        risk = "high";
        score -= 50;
      } else {
        try {
          checks.nonce = parseInt(await rpc<string>(runtime.rpcUrl, "eth_getTransactionCount", [lower, "latest"]), 16);
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
