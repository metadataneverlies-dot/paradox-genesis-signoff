#!/usr/bin/env node
'use strict';
// Check a signed finalize record using only the public keys inside it.
// Usage: node verify.js finalize-out/1-genesis-signoff.json [more.json ...]
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { verifyMessage } = require(path.join(__dirname, 'btcmsg'));
const sha256 = b => crypto.createHash('sha256').update(b).digest('hex');
function canon(v) {
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  if (v && typeof v === 'object')
    return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
  return JSON.stringify(v);
}
let bad = 0;
for (const f of process.argv.slice(2)) {
  const doc = JSON.parse(fs.readFileSync(f, 'utf8'));
  const bytes = Buffer.from(canon(doc.record));
  const keys = new Map(doc.record.signers.map(s => [s.id, crypto.createPublicKey(s.pubkey_pem)]));
  const seen = new Set();
  for (const x of doc.signatures) {
    const pub = keys.get(x.signer);
    if (!pub || seen.has(x.signer)) continue;
    const alg = pub.asymmetricKeyType === 'ed25519' || pub.asymmetricKeyType === 'ed448' ? null : 'sha256';
    if (crypto.verify(alg, bytes, pub, Buffer.from(x.sig, 'base64'))) seen.add(x.signer);
  }
  const need = doc.record.threshold;
  const digestOk = sha256(bytes) === doc.digest_sha256;
  // timestamp checks
  const problems = [];
  const t = Date.parse(doc.record.created_at);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/.test(doc.record.created_at || '') || isNaN(t)) problems.push('created_at not a UTC ISO time');
  else if (t > Date.now() + 5 * 60 * 1000) problems.push('created_at is in the future');
  else if (t < Date.parse('2009-01-03T18:15:05Z')) problems.push('created_at is before Bitcoin block 0');
  const g = doc.record.btc_genesis;
  if (g) {
    if (g.timestamp_unix !== 1231006505) problems.push('block 0 timestamp_unix is not 1231006505');
    if (new Date(g.timestamp_unix * 1000).toISOString().replace('.000', '') !== g.timestamp_utc) problems.push('timestamp_unix and timestamp_utc disagree');
  }
  const lt = doc.record.btc_link_tx;
  if (lt) {
    if (!/^[0-9a-f]{64}$/.test(lt.txid || '')) problems.push('link tx txid malformed');
    if (!(lt.block_time_unix > 1231006505)) problems.push('link tx block time not after block 0');
    if (lt.block_time_unix * 1000 > t) problems.push('link tx is dated after this record was signed');
  }
  const op = doc.record.ownership_proof;
  if (doc.record.link_tx_status === 'owned') {
    const r = op ? verifyMessage(op.address, op.message, op.signature) : { ok: false, why: 'no proof attached' };
    if (!r.ok) problems.push('ownership proof fails: ' + r.why);
  }
  const pass = digestOk && seen.size >= need && problems.length === 0;
  if (!pass) bad++;
  const time = isNaN(t) ? '' : `  signed ${doc.record.created_at}`;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${f}  ${seen.size}-of-${need} valid${digestOk ? '' : ', digest mismatch'}${time}${problems.length ? '  [' + problems.join('; ') + ']' : ''}`);
}
process.exit(bad ? 1 : 0);
