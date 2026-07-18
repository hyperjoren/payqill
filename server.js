const http = require("http");
const { request: httpsRequest } = require("https");
const SECRET = process.env.RELAY_SECRET || "";

http.createServer((req, res) => {
  if (req.method !== "POST") return res.writeHead(405).end();
  if (SECRET && req.headers["x-relay-secret"] !== SECRET) return res.writeHead(401).end("unauthorized");
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    let payload;
    try { payload = JSON.parse(body); } catch { return res.writeHead(400).end("bad json"); }
    const { url, headers } = payload || {};
    if (!url || !/^https:\/\/[a-z0-9.-]+\.bharatpe\.in\//i.test(url)) return res.writeHead(400).end("bad url");
    const u = new URL(url);
    const upstream = httpsRequest(
      { host: u.host, path: u.pathname + u.search, method: "GET", headers: { ...headers, Host: u.host } },
      (r) => {
        let data = "";
        r.on("data", (c) => (data += c));
        r.on("end", () =>
          res
            .writeHead(r.statusCode || 502, { "content-type": r.headers["content-type"] || "text/plain" })
            .end(data)
        );
      }
    );
    upstream.on("error", (e) => res.writeHead(502).end(String(e)));
    upstream.end();
  });
}).listen(process.env.PORT || 3000, () => console.log("relay listening"));
