'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');

const { Store } = require('./lib/store');
const { attach } = require('./lib/tunnel');
const { createApi } = require('./lib/api');

const cfg = {
  port: Number(process.env.PORT || 8080),
  wsPath: process.env.WS_PATH || '/ws',
  adminPassword: process.env.ADMIN_PASSWORD || 'change-me-now'
};

const RULES_FILE = path.join(__dirname, 'rules.json');
let cache = JSON.parse(fs.readFileSync(RULES_FILE, 'utf8'));
let mtime = 0;

function loadRules() {
  const s = fs.statSync(RULES_FILE);
  if (s.mtimeMs !== mtime) { cache = JSON.parse(fs.readFileSync(RULES_FILE, 'utf8')); mtime = s.mtimeMs; }
  return cache;
}
function saveRules(r) { fs.writeFileSync(RULES_FILE, JSON.stringify(r, null, 2)); mtime = 0; loadRules(); }

const log = (t, m) => console.log(`[${new Date().toISOString()}] ${t}: ${m}`);
const store = new Store(path.join(__dirname, 'keys.json'));

const server = http.createServer(createApi({ store, cfg, loadRules, saveRules }));
attach(server, cfg, { store, rulesRef: loadRules, log });

server.listen(cfg.port, () => log('boot', `listening on :${cfg.port} ws=${cfg.wsPath}`));
