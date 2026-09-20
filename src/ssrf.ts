import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

const MAX_BODY_BYTES = 64 * 1024;
const FETCH_TIMEOUT_MS = 8000;
const MAX_REDIRECTS = 3;
const BLOCKED_HOSTS = new Set(["localhost", "metadata", "metadata.google.internal", "host.docker.internal", "internal"]);

export { FETCH_TIMEOUT_MS };

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

export async function fetchLimited(
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

export function parseJsonKeys(text: string, contentType: string): string[] {
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
