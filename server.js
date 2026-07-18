const http = require("http");
const https = require("https");
const dns = require("dns");

const SECRET = process.env.RELAY_SECRET || "";
const PORT = process.env.PORT || 3000;
const MAX_BODY = 256 * 1024;

function send(res, status, body, headers = {}) {
  res.writeHead(status, {
    "content-type": headers["content-type"] || "text/plain; charset=utf-8",
    "cache-control": "no-store",
    ...headers,
  });
  res.end(body);
}

function cleanHeaderValue(value) {
  return String(value ?? "").replace(/[\r\n]+/g, " ").trim();
}

function cleanForwardHeaders(headers, host) {
  const allowed = new Set([
    "accept",
    "accept-language",
    "authorization",
    "cookie",
    "referer",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "token",
    "user-agent",
    "x-access-token",
  ]);
  const out = {};
  for (const [key, raw] of Object.entries(headers || {})) {
    const lower = key.toLowerCase();
    if (!allowed.has(lower)) continue;
    const value = cleanHeaderValue(raw);
    if (value) out[key] = value;
  }
  out.Host = host;
  out.Connection = "close";
  out.Accept = out.Accept || "application/json, text/plain, */*";
  out["User-Agent"] = out["User-Agent"] || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";
  return out;
}

function isAllowedBharatPeUrl(value) {
  try {
    const u = new URL(value);
    return u.protocol === "https:" && /(^|\.)bharatpe\.in$/i.test(u.hostname);
  } catch {
    return false;
  }
}

function forward(url, headers) {
  return new Promise((resolve) => {
    const u = new URL(url);
    const started = Date.now();
    const req = https.request(
      {
        protocol: "https:",
        hostname: u.hostname,
        port: 443,
        path: u.pathname + u.search,
        method: "GET",
        headers: cleanForwardHeaders(headers, u.hostname),
        timeout: 15000,
        family: 4,
        lookup: (hostname, opts, cb) => dns.lookup(hostname, { ...opts, family: 4 }, cb),
      },
      (upstream) => {
        const chunks = [];
        let size = 0;
        upstream.on("data", (chunk) => {
          size += chunk.length;
          if (size <= 1024 * 1024) chunks.push(chunk);
        });
        upstream.on("end", () => {
          const body = Buffer.concat(chunks).toString("utf8");
          console.log("bharatpe", upstream.statusCode, Date.now() - started + "ms", u.hostname + u.pathname, body.slice(0, 120).replace(/\s+/g, " "));
          resolve({
            status: upstream.statusCode || 502,
            body,
            contentType: upstream.headers["content-type"] || "text/plain; charset=utf-8",
          });
        });
      },
    );

    req.on("timeout", () => req.destroy(new Error("upstream timeout")));
    req.on("error", (error) => {
      console.error("bharatpe upstream error", error.code || error.name, error.message, u.hostname + u.pathname);
      resolve({ status: 502, body: `${error.code || "UPSTREAM_ERROR"}: ${error.message}`, contentType: "text/plain; charset=utf-8" });
    });
    req.end();
  });
}

const server = http.createServer((req, res) => {
  try {
    if (req.method === "GET" && req.url === "/health") return send(res, 200, "ok");
    if (req.method !== "POST") return send(res, 405, "method not allowed");
    if (SECRET && req.headers["x-relay-secret"] !== SECRET) return send(res, 401, "unauthorized");

    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > MAX_BODY) req.destroy(new Error("payload too large"));
    });
    req.on("error", (error) => send(res, 400, error.message));
    req.on("end", async () => {
      try {
        const payload = JSON.parse(body || "{}");
        const { url, headers } = payload || {};
        if (!isAllowedBharatPeUrl(url)) return send(res, 400, "bad url");
        const result = await forward(url, headers);
        send(res, result.status, result.body, { "content-type": result.contentType });
      } catch (error) {
        console.error("relay request error", error && error.message ? error.message : error);
        send(res, 500, error && error.message ? error.message : "relay error");
      }
    });
  } catch (error) {
    console.error("relay fatal handler error", error && error.message ? error.message : error);
    send(res, 500, error && error.message ? error.message : "relay error");
  }
});

server.listen(PORT, () => console.log("relay listening", { port: PORT }));
