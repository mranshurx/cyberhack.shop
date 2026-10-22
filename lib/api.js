'use strict';
const fs = require('fs');
const path = require('path');
const { uuidFor } = require('./store');

const MIME = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript', '.json': 'application/json' };

const send = (res, code, obj, h = {}) => {
  const b = Buffer.from(JSON.stringify(obj));
  res.writeHead(code, { 'Content-Type': 'application/json', 'Content-Length': b.length, ...h });
  res.end(b);
};

function cookies(req) {
  const o = {};
  (req.headers.cookie || '').split(';').forEach(p => {
    const i = p.indexOf('=');
    if (i > 0) o[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return o;
}

function readBody(req) {
  return new Promise(r => {
    let d = '';
    req.on('data', c => { d += c; if (d.length > 2e6) req.destroy(); });
    req.on('end', () => { try { r(JSON.parse(d || '{}')); } catch { r({}); } });
  });
}

function publicLink(req, cfg, key) {
  const host = (req.headers['x-forwarded-host'] || req.headers.host || 'localhost').split(':')[0];
  const https = (req.headers['x-forwarded-proto'] || 'http') === 'https';
  const port = https ? 443 : ((req.headers.host || '').split(':')[1] || 80);
  const q = [`type=ws`, `security=${https ? 'tls' : 'none'}`, `path=${encodeURIComponent(cfg.wsPath)}`, `host=${host}`];
  if (https) q.push(`sni=${host}`);
  return `vless://${uuidFor(key)}@${host}:${port}?${q.join('&')}#PHANTOM`;
}

function createApi({ store, cfg, loadRules, saveRules }) {
  const pub = path.join(__dirname, '..', 'public');

  return async function handler(req, res) {
    const url = new URL(req.url, 'http://x');
    const p = url.pathname;

    if (req.method === 'GET' && !p.startsWith('/api/') && !p.startsWith('/sub/')) {
      const file = p === '/' ? 'index.html' : p === '/app' ? 'app.html' : p === '/admin' ? 'admin.html' : p.slice(1);
      const full = path.join(pub, file);
      if (full.startsWith(pub) && fs.existsSync(full) && fs.statSync(full).isFile()) {
        res.writeHead(200, { 'Content-Type': MIME[path.extname(full)] || 'application/octet-stream' });
        return res.end(fs.readFileSync(full));
      }
      res.writeHead(404); return res.end('not found');
    }

    const b = req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH' ? await readBody(req) : {};
    const ck = cookies(req);
    const sess = ck.ph_sess && store.session(ck.ph_sess);

    if (p === '/api/health') return send(res, 200, { ok: true, up: process.uptime() });

    // ---------- auth ----------
    if (p === '/api/redeem' && req.method === 'POST') {
      const key = String(b.key || '').toUpperCase().trim();
      const r = store.get(key);
      if (!r) return send(res, 400, { error: "this key doesn't exist." });
      if (r.expires_at < Date.now()) { store.update(key, { status: 'expired' }); return send(res, 400, { error: 'this key has expired.' }); }
      if (r.status !== 'active') return send(res, 400, { error: `key is ${r.status}.` });
      const t = store.newSession(key);
      return send(res, 200, { ok: true }, { 'Set-Cookie': `ph_sess=${t}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000` });
    }

    if (p === '/api/logout' && req.method === 'POST') {
      if (ck.ph_sess) store.dropSession(ck.ph_sess);
      return send(res, 200, { ok: true }, { 'Set-Cookie': 'ph_sess=; Path=/; Max-Age=0' });
    }

    if (p === '/api/me') {
      if (!sess) return send(res, 401, { error: 'no session' });
      const r = store.get(sess.key);
      if (!r) return send(res, 401, { error: 'gone' });
      return send(res, 200, { key: r.key, status: r.status, expires_at: r.expires_at, features: r.features, last_seen: r.last_seen });
    }

    // ---------- user ----------
    if (p === '/api/features' && req.method === 'POST') {
      if (!sess) return send(res, 401, { error: 'no session' });
      const ids = loadRules().features.map(f => f.id);
      const next = {};
      for (const id of ids) next[id] = !!b.features?.[id];
      store.update(sess.key, { features: next });
      return send(res, 200, { ok: true, features: next });
    }

    if (p === '/api/link') {
      if (!sess) return send(res, 401, { error: 'no session' });
      const link = publicLink(req, cfg, sess.key);
      const sub = `https://${(req.headers['x-forwarded-host'] || req.headers.host || '').replace(/:\d+$/, '')}/sub/${sess.key}`;
      return send(res, 200, {
        ok: true, vless: link, sub,
        happ: `happ://add/${Buffer.from(sub).toString('base64url')}`
      });
    }

    if (p.startsWith('/sub/')) {
      const key = p.slice(5);
      if (!store.get(key)) { res.writeHead(404); return res.end(''); }
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      return res.end(Buffer.from(publicLink(req, cfg, key) + '\n').toString('base64'));
    }

    // ---------- admin ----------
    const isAdmin = ck.ph_admin && store.data.admins[ck.ph_admin];

    if (p === '/api/admin/login' && req.method === 'POST') {
      if (String(b.password || '') !== cfg.adminPassword) return send(res, 401, { error: 'bad password' });
      const t = Math.random().toString(36).slice(2) + Date.now().toString(36);
      store.data.admins[t] = { created: Date.now() }; store.mutate();
      return send(res, 200, { ok: true }, { 'Set-Cookie': `ph_admin=${t}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000` });
    }
    if (p === '/api/admin/logout' && req.method === 'POST') {
      delete store.data.admins[ck.ph_admin]; store.mutate();
      return send(res, 200, { ok: true }, { 'Set-Cookie': 'ph_admin=; Path=/; Max-Age=0' });
    }

    if (p.startsWith('/api/admin/')) {
      if (!isAdmin) return send(res, 401, { error: 'admin only' });

      if (p === '/api/admin/keys' && req.method === 'GET')
        return send(res, 200, { keys: store.list(), online: store.online().map(k => k.key) });
      if (p === '/api/admin/keys' && req.method === 'POST')
        return send(res, 200, { key: store.create({ days: +b.days || 1 }) });
      if (p === '/api/admin/rules' && req.method === 'GET')
        return send(res, 200, { rules: loadRules() });
      if (p === '/api/admin/rules' && req.method === 'PUT') {
        saveRules(b.rules); return send(res, 200, { ok: true });
      }

      const m = p.match(/^\/api\/admin\/keys\/(.+)$/);
      if (m) {
        const key = m[1];
        if (req.method === 'DELETE') { store.remove(key); return send(res, 200, { ok: true }); }
        if (req.method === 'PATCH') {
          const patch = {};
          if (b.status) patch.status = b.status;
          if (b.days) patch.expires_at = Date.now() + b.days * 86400e3;
          if (b.features) patch.features = { ...store.get(key).features, ...b.features };
          return send(res, 200, { key: store.update(key, patch) });
        }
      }
    }

    send(res, 404, { error: 'not found' });
  };
}

module.exports = { createApi };
