// VLESS + Trojan over WebSocket proxy (Node.js, for alwaysdata free hosting).
// Same UUID value is used as the VLESS uuid and as the Trojan password.
// Routes: VLESS on "/" and "/vless", Trojan on "/trojan".
// Listens on process.env.PORT (assigned by the platform) or 8080 locally.
const http = require("http");
const net = require("net");
const crypto = require("crypto");
const { WebSocketServer } = require("ws");

const UUID_STR = process.env.UUID || "e6a861ce-8491-4f82-9920-d07db7ee09d0";
const UUID_HEX = UUID_STR.replace(/-/g, "").toLowerCase();
const TROJAN_HASH = crypto.createHash("sha224").update(UUID_STR).digest("hex"); // 56 hex chars
const PORT = parseInt(process.env.PORT || "8080", 10);

const server = http.createServer((req, res) => {
  if (req.url === "/health") {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("ok");
    return;
  }
  res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
  res.end("<!DOCTYPE html><html><head><meta charset='utf-8'><title>Welcome</title></head>" +
    "<body><h1>Welcome</h1><p>This site is under construction.</p></body></html>");
});

const wss = new WebSocketServer({ server });

function parseAddr(buf, pos) {
  const atyp = buf[pos];
  pos += 1;
  if (atyp === 1) {
    return { host: `${buf[pos]}.${buf[pos + 1]}.${buf[pos + 2]}.${buf[pos + 3]}`, next: pos + 4 };
  } else if (atyp === 2) {
    const len = buf[pos];
    return { host: buf.toString("utf8", pos + 1, pos + 1 + len), next: pos + 1 + len };
  } else if (atyp === 3) {
    const parts = [];
    for (let i = 0; i < 8; i++) parts.push(buf.readUInt16BE(pos + i * 2).toString(16));
    return { host: parts.join(":"), next: pos + 16 };
  }
  throw new Error("bad atyp");
}

function parseVless(buf) {
  if (buf.length < 22) throw new Error("short");
  if (buf.toString("hex", 1, 17) !== UUID_HEX) throw new Error("bad uuid");
  const optLen = buf[17];
  const cmd = buf[18 + optLen];
  if (cmd !== 1) throw new Error("only tcp");
  const port = buf.readUInt16BE(19 + optLen);
  const { host, next } = parseAddr(buf, 21 + optLen);
  return { host, port, payload: buf.subarray(next), version: buf[0] };
}

function parseTrojan(buf) {
  // hash(56 ascii) CRLF(2) cmd(1) atyp+addr port(2) CRLF(2) payload
  if (buf.length < 60) throw new Error("short");
  if (buf.toString("ascii", 0, 56) !== TROJAN_HASH) throw new Error("bad password");
  const cmd = buf[58];
  if (cmd !== 1) throw new Error("only connect");
  const { host, next } = parseAddr(buf, 59);
  const port = buf.readUInt16BE(next);
  return { host, port, payload: buf.subarray(next + 4), version: -1 };
}

wss.on("connection", (ws, req) => {
  const isTrojan = (req.url || "").startsWith("/trojan");
  let upstream = null;
  let connecting = false;
  const pending = [];

  ws.on("message", (raw) => {
    const data = Buffer.isBuffer(raw) ? raw : Buffer.from(raw);
    if (upstream) {
      upstream.write(data);
      return;
    }
    if (connecting) {
      pending.push(data);
      return;
    }
    connecting = true;
    let parsed;
    try {
      parsed = isTrojan ? parseTrojan(data) : parseVless(data);
    } catch {
      ws.close();
      return;
    }
    upstream = net.connect(parsed.port, parsed.host, () => {
      if (parsed.version >= 0) ws.send(Buffer.from([parsed.version, 0])); // VLESS response header
      if (parsed.payload.length) upstream.write(parsed.payload);
      for (const p of pending) upstream.write(p);
      pending.length = 0;
    });
    upstream.on("data", (chunk) => {
      if (ws.readyState === ws.OPEN) ws.send(chunk);
    });
    upstream.on("end", () => ws.close());
    upstream.on("error", () => ws.close());
  });

  ws.on("close", () => { if (upstream) upstream.destroy(); });
  ws.on("error", () => { if (upstream) upstream.destroy(); });
});

server.listen(PORT, () => {
  console.log("listening on", PORT);
});
