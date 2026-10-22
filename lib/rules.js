'use strict';

function matches(rule, buf) {
  if (rule.len && (buf.length < rule.len[0] || buf.length > rule.len[1])) return false;
  if (rule.bytes) for (const off in rule.bytes) if (buf[+off] !== parseInt(rule.bytes[off], 16)) return false;
  return true;
}

function patchOnce(ops, buf) {
  const b = Buffer.from(buf);
  for (const op of ops) {
    if (op.off >= b.length) continue;
    b[op.off] = op.set !== undefined ? (op.set & 0xff) : ((b[op.off] + (op.add || 0)) & 0xff);
  }
  return b;
}

function apply(features, dir, buf, rules) {
  const out = [buf];
  for (const f of rules.features) {
    if (f.dir !== dir || !features.has(f.id)) continue;
    if (f.patch && f.patch.length && matches(f.match, buf)) out[0] = patchOnce(f.patch, out[0]);
  }
  for (const f of rules.features) {
    if (f.dir !== dir || !features.has(f.id)) continue;
    if (f.repeat > 1 && matches(f.match, buf)) while (out.length < f.repeat) out.push(Buffer.from(out[0]));
  }
  return out;
}

module.exports = { apply, matches };
