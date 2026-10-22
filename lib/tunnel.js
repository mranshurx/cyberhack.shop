'use strict';
const crypto = require('crypto');
const net = require('net');
const dgram = require('dgram');
const rules = require('./rules');
const { uuidFromBytes } = require('./store');

const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

function acceptKey(k) { return crypto.createHash('sha1').update(k + GUID).digest('base64'); }

function frame(payload, op = 0x2) {
  const n = payload.length;
  let h;
  if (n < 126) { h = Buffer.alloc(2); h[1] = n; }
  else if (n < 65536) { h = Buffer.alloc(4); h[1] = 126; h.writeUInt16BE(n, 2); }
  else { h = Buffer.alloc(10); h[1] = 127; h.writeBigUInt64BE(BigInt(n), 2); }
  h[0] = 0x80 | op;
  return Buffer.concat([h, payload]);
}

const u16 = n => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };

class Conn {
  constructor(sock, rawSeed, streamSeed, ctx) {
    this.sock = sock; this.ctx = ctx;
    this.raw = Buffer.from(rawSeed || []);        // websocket layer bytes
    this.stream = Buffer.from(streamSeed || []);  // vless layer bytes
    this.headerDone = false; this.dead = false;
    this.key = null; this.dst = null; this.cmd = 0;
    this.tcp = null; this.udp = null;

    sock.on('data', d => this.onRaw(d));
    sock.on('error', () => this.close());
    sock.on('close', () => this.close());
    sock.setNoDelay(true);

    this.ping = setInterval(() => { if (!this.dead) this.sock.write(frame(Buffer.alloc(0), 0x9)); }, 25000);
    this.ping.unref();

    if (this.stream.length && this.parseHeader()) this.pump();
  }

  onRaw(d) {
    this.raw = Buffer.concat([this.raw, d]);
    while (!this.dead) {
      const f = this.readFrame();
      if (!f) break;
      if (f.op === 0x8) return this.close();
      if (f.op === 0x9) { this.sock.write(frame(f.payload, 0xA)); continue; }
      if (f.op === 0xA) continue;
      this.feed(f.payload);
    }
  }

  readFrame() {
    const b = this.raw;
    if (b.length < 2) return null;
    const op = b[0] & 0x0f, masked = b[1] & 0x80;
    let len = b[1] & 0x7f, off = 2;
    if (len === 126) { if (b.length < 4) return null; len = b.readUInt16BE(2); off = 4; }
    else if (len === 127) { if (b.length < 10) return null; len = Number(b.readBigUInt64BE(2)); off = 10; }
    const ml = masked ? 4 : 0;
    if (b.length < off + ml + len) return null;
    const mask = masked ? b.subarray(off, off + 4) : null;
    const payload = Buffer.from(b.subarray(off + ml, off + ml + len));
    if (mask) for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3];
    this.raw = b.subarray(off + ml + len);
    return { op, payload };
  }

  feed(d) {
    this.stream = Buffer.concat([this.stream, d]);
    if (!this.headerDone && !this.parseHeader()) return;
    this.pump();
  }

  parseHeader() {
    const b = this.stream;
    if (b.length < 18) return false;
    const uuid = uuidFromBytes(b.subarray(1, 17));
    const alen = b[17];
    let o = 18 + alen;
    if (b.length < o + 4) return false;
    const cmd = b[o++];
    const port = b.readUInt16BE(o); o += 2;
    const at = b[o++];
    let host;
    if (at === 1) { if (b.length < o + 4) return false; host = `${b[o]}.${b[o+1]}.${b[o+2]}.${b[o+3]}`; o += 4; }
    else if (at === 2) { if (b.length < o + 1) return false; const l = b[o++]; if (b.length < o + l) return false; host = b.subarray(o, o + l).toString(); o += l; }
    else if (at === 3) { if (b.length < o + 16) return false; o += 16; host = '::1'; }
    else return false;

    this.headerDone = true;
    this.stream = b.subarray(o);
    this.cmd = cmd;
    this.dst = { host, port };
    this.key = this.ctx.store.keyForUuid(uuid);
    this.ctx.log('tunnel', `${cmd === 2 ? 'udp' : cmd === 1 ? 'tcp' : 'MUX?'} -> ${host}:${port} key=${this.key || 'unknown'}`);

    this.sock.write(frame(Buffer.from([0x00, 0x00])));   // vless response header

    if (cmd === 2) this.openUdp();
    else if (cmd === 1) this.openTcp();
    else { this.ctx.log('tunnel', 'Mux detected — turn Mux OFF in the client'); this.openUdp(); }
    return true;
  }

  features() {
    const r = this.key && this.ctx.store.get(this.key);
    if (!r || r.status !== 'active' || r.expires_at < Date.now()) return new Set();
    return new Set(Object.keys(r.features).filter(f => r.features[f]));
  }

  openUdp() {
    this.udp = dgram.createSocket('udp4');
    this.udp.on('error', () => {});
    this.udp.on('message', m => {
      for (const p of rules.apply(this.features(), 's2c', m, this.ctx.rulesRef()))
        this.write(Buffer.concat([u16(p.length), p]));
    });
    this.ctx.store.seen(this.key);
  }

  openTcp() {
    this.tcp = net.connect(this.dst.port, this.dst.host);
    this.tcp.setNoDelay(true);
    this.tcp.on('data', d => this.write(d));
    this.tcp.on('error', () => this.close());
    this.tcp.on('close', () => this.close());
    if (this.stream.length) { this.tcp.write(this.stream); this.stream = Buffer.alloc(0); }
  }

  pump() {
    if (this.cmd === 1) {
      if (this.tcp && this.stream.length) { this.tcp.write(this.stream); this.stream = Buffer.alloc(0); }
      return;
    }
    while (this.stream.length >= 2) {
      const n = this.stream.readUInt16BE(0);
      if (this.stream.length < 2 + n) break;
      const d = this.stream.subarray(2, 2 + n);
      this.stream = this.stream.subarray(2 + n);
      if (this.key) this.ctx.store.seen(this.key);
      for (const p of rules.apply(this.features(), 'c2s', d, this.ctx.rulesRef()))
        this.udp.send(p, this.dst.port, this.dst.host);
    }
  }

  write(buf) { if (!this.dead) this.sock.write(frame(buf)); }

  close() {
    if (this.dead) return;
    this.dead = true;
    clearInterval(this.ping);
    try { this.tcp && this.tcp.destroy(); } catch {}
    try { this.udp && this.udp.close(); } catch {}
    try { this.sock.destroy(); } catch {}
  }
}

function attach(server, cfg, ctx) {
  server.on('upgrade', (req, socket, head) => {
    let path = '/';
    try { path = new URL(req.url, 'http://x').pathname; } catch {}
    if (path !== cfg.wsPath) return socket.destroy();
    const k = req.headers['sec-websocket-key'];
    if (!k) return socket.destroy();

    const hs = [
      'HTTP/1.1 101 Switching Protocols',
      'Upgrade: websocket',
      'Connection: Upgrade',
      'Sec-WebSocket-Accept: ' + acceptKey(k)
    ];

    // xray "early data": first VLESS bytes may arrive in Sec-WebSocket-Protocol
    let early = Buffer.alloc(0);
    const proto = req.headers['sec-websocket-protocol'];
    if (proto) {
      try {
        const d = Buffer.from(proto, 'base64');
        if (d.length && d[0] === 0) { early = d; hs.push('Sec-WebSocket-Protocol: ' + proto); }
      } catch {}
    }

    socket.write(hs.join('\r\n') + '\r\n\r\n');
    new Conn(socket, head, early, ctx);
  });
}

module.exports = { attach, Conn };
