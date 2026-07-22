const http = require("http");
const https = require("https");
const dns = require("dns");
const tls = require("tls");

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
    "accept","accept-language","authorization","cookie","referer",
    "sec-ch-ua","sec-ch-ua-mobile","sec-ch-ua-platform",
    "sec-fetch-dest","sec-fetch-mode","sec-fetch-site",
    "token","user-agent","x-access-token","x-xsrf-token","x-requested-with","content-type","origin",
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
  } catch { return false; }
}

function forward(url, headers, method = "GET", body) {
  return new Promise((resolve) => {
    const u = new URL(url);
    const started = Date.now();
    const hdrs = cleanForwardHeaders(headers, u.hostname);
    if (body != null) {
      hdrs["Content-Length"] = Buffer.byteLength(body);
      if (!hdrs["Content-Type"] && !hdrs["content-type"]) hdrs["Content-Type"] = "application/x-www-form-urlencoded";
    }
    const req = https.request({
      protocol: "https:", hostname: u.hostname, port: 443,
      path: u.pathname + u.search, method,
      headers: hdrs,
      timeout: 15000, family: 4,
      lookup: (hostname, opts, cb) => dns.lookup(hostname, { ...opts, family: 4 }, cb),
    }, (upstream) => {
      const chunks = []; let size = 0;
      upstream.on("data", (chunk) => { size += chunk.length; if (size <= 1024 * 1024) chunks.push(chunk); });
      upstream.on("end", () => {
        const buf = Buffer.concat(chunks).toString("utf8");
        console.log("bharatpe", method, upstream.statusCode, Date.now() - started + "ms", u.hostname + u.pathname);
        resolve({ status: upstream.statusCode || 502, body: buf, headers: upstream.headers, contentType: upstream.headers["content-type"] || "text/plain; charset=utf-8" });
      });
    });
    req.on("timeout", () => req.destroy(new Error("upstream timeout")));
    req.on("error", (error) => {
      console.error("bharatpe upstream error", error.code || error.name, error.message);
      resolve({ status: 502, body: `${error.code || "UPSTREAM_ERROR"}: ${error.message}`, headers: {}, contentType: "text/plain; charset=utf-8" });
    });
    if (body != null) req.write(body);
    req.end();
  });
}

// ============ Minimal IMAP client (Gmail read-only) ============
function imapSearch({ user, pass, gmailQuery, limit = 10, timeoutMs = 20000 }) {
  return new Promise((resolve, reject) => {
    const host = "imap.gmail.com";
    const socket = tls.connect({ host, port: 993, servername: host });
    let buffer = "";
    let tagCounter = 0;
    let done = false;
    const finish = (err, val) => { if (done) return; done = true; try { socket.destroy(); } catch {} err ? reject(err) : resolve(val); };
    const timer = setTimeout(() => finish(new Error("IMAP timeout")), timeoutMs);

    const quote = (s) => `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;

    const waiters = []; // { re, resolve }
    const feed = (chunk) => {
      buffer += chunk;
      for (let i = 0; i < waiters.length; i++) {
        const w = waiters[i];
        const m = w.re.exec(buffer);
        if (m) {
          const end = m.index + m[0].length;
          const out = buffer.slice(0, end);
          buffer = buffer.slice(end);
          waiters.splice(i, 1); i--;
          w.resolve(out);
        }
      }
    };
    const waitFor = (re) => new Promise((res) => waiters.push({ re, resolve: res }));
    socket.setEncoding("binary");
    socket.on("data", (d) => feed(d));
    socket.on("error", (e) => finish(e));
    socket.on("close", () => finish(new Error("IMAP closed")));

    const cmd = async (line) => {
      const tag = "A" + (++tagCounter);
      socket.write(tag + " " + line + "\r\n");
      return waitFor(new RegExp(`(^|\\r\\n)${tag} (OK|NO|BAD)[^\\r\\n]*\\r\\n`));
    };

    (async () => {
      try {
        await waitFor(/^\* (OK|PREAUTH)[^\r\n]*\r\n/);
        const login = await cmd(`LOGIN ${quote(user)} ${quote(pass)}`);
        if (!/ OK/.test(login)) throw new Error("IMAP login failed");
        await cmd("SELECT INBOX");
        const searchResp = await cmd(`UID SEARCH X-GM-RAW ${quote(gmailQuery)}`);
        const searchLine = /\* SEARCH([^\r\n]*)/.exec(searchResp);
        const uids = (searchLine?.[1] ?? "").trim().split(/\s+/).filter(Boolean).map((n) => parseInt(n, 10)).filter(Number.isFinite);
        if (uids.length === 0) {
          try { await cmd("LOGOUT"); } catch {}
          clearTimeout(timer);
          return finish(null, { messages: [] });
        }
        const targetUids = uids.slice(-limit).reverse();
        const fetchTag = "A" + (++tagCounter);
        socket.write(`${fetchTag} UID FETCH ${targetUids.join(",")} (UID BODY.PEEK[HEADER.FIELDS (SUBJECT FROM DATE)] BODY.PEEK[TEXT])\r\n`);
        const raw = await waitFor(new RegExp(`(^|\\r\\n)${fetchTag} (OK|NO|BAD)[^\\r\\n]*\\r\\n`));
        try { await cmd("LOGOUT"); } catch {}
        clearTimeout(timer);
        const messages = parseFetch(raw);
        finish(null, { messages });
      } catch (e) {
        clearTimeout(timer);
        finish(e);
      }
    })();
  });
}

function parseFetch(raw) {
  const results = [];
  const blockRe = /\* (\d+) FETCH \(/g;
  const indexes = [];
  let m;
  while ((m = blockRe.exec(raw)) !== null) indexes.push(m.index);
  indexes.push(raw.length);
  for (let i = 0; i < indexes.length - 1; i++) {
    const block = raw.slice(indexes[i], indexes[i + 1]);
    const uidM = /UID (\d+)/.exec(block);
    const uid = uidM ? parseInt(uidM[1], 10) : NaN;
    const literals = [];
    let cursor = 0;
    while (true) {
      const litRe = /\{(\d+)\}\r\n/g;
      litRe.lastIndex = cursor;
      const lm = litRe.exec(block);
      if (!lm) break;
      const size = parseInt(lm[1], 10);
      const start = lm.index + lm[0].length;
      literals.push(block.slice(start, start + size));
      cursor = start + size;
    }
    const headers = (literals[0] || "").replace(/\r?\n[\t ]+/g, " ");
    const body = literals[1] || "";
    const subj = /^Subject:\s*(.*)$/im.exec(headers)?.[1]?.trim() || "";
    const from = /^From:\s*(.*)$/im.exec(headers)?.[1]?.trim() || "";
    const dateStr = /^Date:\s*(.*)$/im.exec(headers)?.[1]?.trim();
    if (!Number.isFinite(uid)) continue;
    results.push({ uid, subject: decodeMimeWord(subj), from, date: dateStr || null, body });
  }
  return results;
}

function decodeMimeWord(s) {
  return s.replace(/=\?([^?]+)\?([BQ])\?([^?]+)\?=/gi, (_, cs, enc, data) => {
    try {
      const charset = String(cs || "utf-8").toLowerCase();
      if (enc.toUpperCase() === "B") return Buffer.from(data, "base64").toString(charset);
      const q = data.replace(/_/g, " ").replace(/=([0-9A-F]{2})/gi, (_, h) => String.fromCharCode(parseInt(h, 16)));
      return Buffer.from(q, "binary").toString(charset);
    } catch { return data; }
  });
}

const server = http.createServer((req, res) => {
  try {
    if (req.method === "GET" && req.url === "/health") return send(res, 200, "ok");
    if (req.method !== "POST") return send(res, 405, "method not allowed");
    if (SECRET && req.headers["x-relay-secret"] !== SECRET) return send(res, 401, "unauthorized");

    let body = "";
    req.on("data", (chunk) => { body += chunk; if (body.length > MAX_BODY) req.destroy(new Error("payload too large")); });
    req.on("error", (error) => send(res, 400, error.message));
    req.on("end", async () => {
      try {
        const payload = JSON.parse(body || "{}");
        if (req.url === "/imap/fampay-search") {
          const { user, pass, query, limit } = payload;
          if (!user || !pass || !query) return send(res, 400, "missing user/pass/query");
          try {
            const started = Date.now();
            const result = await imapSearch({ user, pass, gmailQuery: query, limit: limit || 10 });
            console.log("imap", user, result.messages.length, Date.now() - started + "ms");
            return send(res, 200, JSON.stringify(result), { "content-type": "application/json" });
          } catch (e) {
            console.error("imap error", e.message);
            return send(res, 502, JSON.stringify({ error: e.message }), { "content-type": "application/json" });
          }
        }
        if (req.url === "/rich") {
          const { url, method, headers, body: reqBody } = payload || {};
          if (!isAllowedBharatPeUrl(url)) return send(res, 400, "bad url");
          const result = await forward(url, headers || {}, (method || "GET").toUpperCase(), reqBody);
          const sc = result.headers && (result.headers["set-cookie"] || result.headers["Set-Cookie"]);
          const outHeaders = {};
          if (sc) outHeaders["set-cookie"] = Array.isArray(sc) ? sc : [sc];
          if (result.contentType) outHeaders["content-type"] = result.contentType;
          return send(res, 200, JSON.stringify({ status: result.status, headers: outHeaders, body: result.body }), { "content-type": "application/json" });
        }
        // default: bharatpe forward (GET only, body-only response)
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
