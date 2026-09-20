import http from "node:http";
import { Readable } from "node:stream";

export function incomingToRequest(req: http.IncomingMessage): Request {
  const host = req.headers.host || "127.0.0.1";
  const url = `http://${host}${req.url || "/"}`;
  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers)) {
    if (value === undefined) continue;
    if (Array.isArray(value)) headers.set(key, value.join(", "));
    else headers.set(key, value);
  }
  const method = (req.method || "GET").toUpperCase();
  const hasBody = method !== "GET" && method !== "HEAD";
  return new Request(url, {
    method,
    headers,
    body: hasBody ? Readable.toWeb(req) : undefined,
    duplex: hasBody ? "half" : undefined,
  } as RequestInit);
}

export async function writeNodeResponse(res: http.ServerResponse, response: Response, method: string): Promise<void> {
  const headers: http.OutgoingHttpHeaders = {};
  response.headers.forEach((value, key) => {
    if (key === "content-length" || key === "transfer-encoding") return;
    headers[key] = value;
  });
  const contentType = String(response.headers.get("content-type") || "");
  const isStream = contentType.includes("text/event-stream");

  if (method === "HEAD") {
    const buf = Buffer.from(await response.arrayBuffer());
    headers["content-length"] = buf.byteLength;
    res.writeHead(response.status, headers);
    res.end();
    return;
  }

  if (isStream && response.body) {
    res.writeHead(response.status, headers);
    const reader = response.body.getReader();
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value && value.byteLength) {
          const ok = res.write(Buffer.from(value));
          if (!ok) await new Promise<void>((resolve) => res.once("drain", resolve));
        }
      }
    } finally {
      res.end();
    }
    return;
  }

  const buf = Buffer.from(await response.arrayBuffer());
  headers["content-length"] = buf.byteLength;
  res.writeHead(response.status, headers);
  res.end(buf);
}
