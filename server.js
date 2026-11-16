const http = require('http');
const net = require('net');
const { WebSocketServer } = require('ws');
const { randomUUID } = require('crypto');

const PORT = process.env.PORT || 3000;
const UUID = (process.env.UUID || randomUUID()).replace(/-/g, '');
const uuidBytes = Buffer.from(UUID, 'hex');

const server = http.createServer((req, res) => {
  if (req.url === '/health') { res.writeHead(200, {'Content-Type':'text/plain'}); return res.end('ok'); }
  res.writeHead(200, {'Content-Type':'text/html; charset=utf-8'});
  res.end('<!doctype html><html><head><title>Welcome</title></head><body><h1>It works!</h1><p>This is a personal web service.</p></body></html>');
});

const wss = new WebSocketServer({ server });

wss.on('connection', (ws) => {
  let target = null;
  let first = true;
  ws.on('message', (data) => {
    const msg = Buffer.isBuffer(data) ? data : Buffer.from(data);
    if (!first) { if (target && !target.destroyed) target.write(msg); return; }
    first = false;
    try {
      // VLESS header: ver(1) uuid(16) addonLen(1) addon(n) cmd(1) port(2) addrType(1) addr
      if (msg.length < 24) return ws.close();
      if (!msg.subarray(1, 17).equals(uuidBytes)) return ws.close();
      let idx = 17;
      const addonLen = msg[idx]; idx += 1 + addonLen;
      const cmd = msg[idx]; idx += 1;
      if (cmd !== 1) return ws.close(); // TCP only
      const port = msg.readUInt16BE(idx); idx += 2;
      const atype = msg[idx]; idx += 1;
      let host;
      if (atype === 1) { host = Array.from(msg.subarray(idx, idx + 4)).join('.'); idx += 4; }
      else if (atype === 2) { const len = msg[idx]; idx += 1; host = msg.subarray(idx, idx + len).toString(); idx += len; }
      else if (atype === 3) { const parts = []; for (let i = 0; i < 8; i++) parts.push(msg.readUInt16BE(idx + i * 2).toString(16)); host = parts.join(':'); idx += 16; }
      else return ws.close();
      const rest = msg.subarray(idx);
      target = net.connect(port, host, () => {
        ws.send(Buffer.concat([Buffer.from([msg[0], 0]), rest.length ? Buffer.alloc(0) : Buffer.alloc(0)]));
        if (rest.length) target.write(rest);
      });
      target.on('data', (chunk) => { if (ws.readyState === ws.OPEN) ws.send(chunk); });
      target.on('error', () => { try { ws.close(); } catch {} });
      target.on('close', () => { try { ws.close(); } catch {} });
    } catch { try { ws.close(); } catch {} }
  });
  ws.on('close', () => { if (target && !target.destroyed) target.destroy(); });
  ws.on('error', () => { if (target && !target.destroyed) target.destroy(); });
});

server.listen(PORT, () => console.log('listening on ' + PORT));

// keep-alive self ping (Render provides RENDER_EXTERNAL_URL)
const ext = process.env.RENDER_EXTERNAL_URL;
if (ext) setInterval(() => { try { http.get(ext + '/health', (r) => r.resume()).on('error', () => {}); } catch {} }, 10 * 60 * 1000);
