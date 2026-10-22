'use strict';
const fs = require('fs');
const crypto = require('crypto');

const CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

function seg(n = 4) {
  const b = crypto.randomBytes(n);
  let s = '';
  for (let i = 0; i < n; i++) s += CHARS[b[i] % CHARS.length];
  return s;
}

function uuidFor(key) {
  const h = crypto.createHash('md5').update('phantom:' + key).digest('hex');
  return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20,32)}`;
}
function uuidFromBytes(b) {
  const h = Buffer.from(b).toString('hex');
  return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20,32)}`;
}

const DAY = 86400e3;

class Store {
  constructor(file) {
    this.file = file;
    this.data = fs.existsSync(file)
      ? JSON.parse(fs.readFileSync(file, 'utf8'))
      : { keys: {}, sessions: {}, admins: {} };
    this.dirty = false;
    this._uuidDirty = true;
    this._map = new Map();
    setInterval(() => this.flush(), 3000).unref();
  }

  flush() { if (this.dirty) { fs.writeFileSync(this.file, JSON.stringify(this.data, null, 2)); this.dirty = false; } }
  touch() { this.dirty = true; }
  mutate() { this.dirty = true; this._uuidDirty = true; }

  create({ days = 1 } = {}) {
    let k;
    do { k = `PHTM-${seg()}-${seg()}-${seg()}`; } while (this.data.keys[k]);
    this.data.keys[k] = {
      key: k, status: 'active', created: Date.now(),
      expires_at: Date.now() + days * DAY,
      features: { headshot: false, moco: false, hitdup: false },
      last_seen: 0
    };
    this.mutate();
    return this.data.keys[k];
  }

  get(k) { return this.data.keys[k]; }
  list() { return Object.values(this.data.keys).sort((a, b) => b.created - a.created); }
  remove(k) { delete this.data.keys[k]; this.mutate(); }
  update(k, p) { const r = this.data.keys[k]; if (!r) return null; Object.assign(r, p); this.mutate(); return r; }

  uuidMap() {
    if (this._uuidDirty) {
      this._map = new Map();
      for (const k of Object.keys(this.data.keys)) this._map.set(uuidFor(k), k);
      this._uuidDirty = false;
    }
    return this._map;
  }
  keyForUuid(u) { return this.uuidMap().get(u) || null; }

  newSession(key) {
    const t = crypto.randomBytes(24).toString('hex');
    this.data.sessions[t] = { key, created: Date.now() };
    this.mutate();
    return t;
  }
  session(t) { return this.data.sessions[t]; }
  dropSession(t) { delete this.data.sessions[t]; this.mutate(); }

  seen(key) { const r = this.data.keys[key]; if (r) { r.last_seen = Date.now(); this.dirty = true; } }
  online(ms = 60e3) { const n = Date.now(); return this.list().filter(k => n - (k.last_seen || 0) < ms); }
}

module.exports = { Store, uuidFor, uuidFromBytes, DAY };
