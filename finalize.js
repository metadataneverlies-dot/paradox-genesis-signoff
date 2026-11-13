#!/usr/bin/env node
'use strict';
// PARADOX finalize: builds the finalize records and signs each one 3-of-3
// with your signer PEMs. Runs only on your machine; private keys are read
// from disk, used in memory, and never written or sent anywhere.
//
// Usage:
//   node finalize.js --signers a.pem b.pem c.pem [--main-tip HASH --bot-tip HASH] [--proof-sig BASE64] [--out DIR]
//
// --proof-sig: a signed message from the link tx's sending address bc1qx7avk4…z9fhz3,
// signing exactly this text (see PROOF_MESSAGE below):
//   PARADOX genesis: I made Bitcoin transaction d86bdcbcac4fc73ddc6a7383d85ad902e09333ba9a26f67a41b5908f33757476
//
// Default signers: ./keys/signers/signer1.pem signer2.pem signer3.pem
// The join record is only built when both --main-tip and --bot-tip are given
// (the current tip block hashes of chain-fingerprint and paradox-bot-kit).

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ---------- args ----------
const argv = process.argv.slice(2);
function opt(name) { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : undefined; }
function list(name) {
  const i = argv.indexOf(name); if (i < 0) return undefined;
  const out = []; for (let j = i + 1; j < argv.length && !argv[j].startsWith('--'); j++) out.push(argv[j]);
  return out;
}
const HERE = __dirname;
const signerPaths = list('--signers') ||
  [1, 2, 3].map(n => path.join(process.cwd(), 'keys', 'signers', `signer${n}.pem`));
const outDir = opt('--out') || path.join(process.cwd(), 'finalize-out');
const mainTip = opt('--main-tip');
const botTip = opt('--bot-tip');
const THRESHOLD = 3;
const proofSig = opt('--proof-sig');
const { verifyMessage } = require('./btcmsg');
const PROOF_ADDRESS = 'bc1qx7avk4smhrvpnjpm4p8ukzp6xleguuc7z9fhz3';
const PROOF_MESSAGE = 'PARADOX genesis: I made Bitcoin transaction d86bdcbcac4fc73ddc6a7383d85ad902e09333ba9a26f67a41b5908f33757476';

// ---------- helpers ----------
const sha256 = b => crypto.createHash('sha256').update(b).digest('hex');
function canon(v) { // deterministic JSON, object keys sorted
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  if (v && typeof v === 'object')
    return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
  return JSON.stringify(v);
}
const algFor = key => (key.asymmetricKeyType === 'ed25519' || key.asymmetricKeyType === 'ed448') ? null : 'sha256';
function fail(msg) { console.error('ERROR: ' + msg); process.exit(1); }

// ---------- load signers ----------
if (signerPaths.length !== THRESHOLD) fail(`need exactly ${THRESHOLD} signer PEMs, got ${signerPaths.length}`);
const signers = signerPaths.map(p => {
  if (!fs.existsSync(p)) fail(`signer PEM not found: ${p}`);
  let priv;
  try { priv = crypto.createPrivateKey(fs.readFileSync(p)); }
  catch (e) { fail(`${p} is not a private key PEM (${e.message})`); }
  const pubPem = crypto.createPublicKey(priv).export({ type: 'spki', format: 'pem' });
  return { file: path.basename(p), priv, pubPem, id: sha256(pubPem).slice(0, 16), type: priv.asymmetricKeyType };
});
if (new Set(signers.map(s => s.id)).size !== THRESHOLD) fail('signer PEMs are not 3 distinct keys');

// ---------- Bitcoin block 0 reference (from the decoded coinbase) ----------
const BTC_GENESIS = {
  height: 0,
  date: '2009-01-03',
  timestamp_unix: 1231006505,
  timestamp_utc: '2009-01-03T18:15:05Z',
  block_hash: '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f',
  coinbase_txid: '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b',
  merkle_root: '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b',
  nbits: '1d00ffff',
  headline: 'The Times 03/Jan/2009 Chancellor on brink of second bailout for banks',
  coinbase_pubkey: '04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f',
  pubkey_hash160: '62e907b15cbf27d5425399ebf6f0fb50ebb88f18',
  reward_btc: '50.00000000',
};
// The user's own Bitcoin transaction that pays the genesis key and commits a hash.
const BTC_LINK_TX = {
  txid: 'd86bdcbcac4fc73ddc6a7383d85ad902e09333ba9a26f67a41b5908f33757476',
  block_height: 963249,
  block_hash: '00000000000000000000078011769e060f083326399dfd9c4bd5513decc0a73b',
  block_time_unix: 1787197000,
  genesis_key_output: { vout: 1, sats: 777, type: 'p2pk' },
  op_return: { vout: 2, label: 'CILADABLOCOSBTC', hash: '9ba85b11207439fda75e55ddd19496e8196a2cf0c7b84fe914dfd8202c53edd2' },
};
const PEM_HASHES = {
  'genesis_pubkey_uncompressed.pem': 'acda77fbd22896a8abbe001bf3aab3fe812729ea039b961500830960ee4fbc24',
  'genesis_pubkey_compressed.pem': 'c8a3658e6a72f962d8ce0b980e9fdaa7406bad2f8e0dfbcb4c896f97da807a6e',
};
// If the PEM files sit next to this script, check they are the originals.
for (const [f, h] of Object.entries(PEM_HASHES)) {
  const p = path.join(HERE, f);
  if (fs.existsSync(p) && sha256(fs.readFileSync(p)) !== h) fail(`${f} does not match its recorded hash`);
}

// ---------- ownership of the link tx ----------
// Without --proof-sig the record only cites the transaction. With a valid
// signed message from the sending address, it records ownership plus the proof.
function ownership() {
  if (!proofSig) return { link_tx_status: 'cited', note: 'Cites btc_link_tx; ownership not proven in this record.' };
  const v = verifyMessage(PROOF_ADDRESS, PROOF_MESSAGE, proofSig);
  if (!v.ok) fail('--proof-sig does not verify for ' + PROOF_ADDRESS + ': ' + v.why);
  return { link_tx_status: 'owned', ownership_proof: { address: PROOF_ADDRESS, message: PROOF_MESSAGE, signature: proofSig, pubkey: v.pubkey } };
}

// ---------- records ----------
const createdAt = new Date().toISOString();
const signerSet = signers.map(s => ({ id: s.id, type: s.type, pubkey_pem: s.pubPem }));
const records = [
  {
    name: '1-genesis-signoff',
    body: {
      kind: 'paradox.genesis_signoff', version: 1, created_at: createdAt,
      statement: 'PARADOX genesis sign-off. References Bitcoin block 0 as its anchor point; does not claim control of the Bitcoin genesis key.',
      btc_genesis: BTC_GENESIS,
      btc_link_tx: BTC_LINK_TX,
      ...ownership(),
      threshold: THRESHOLD, signers: signerSet,
    },
  },
  {
    name: '2-pem-anchor',
    body: {
      kind: 'paradox.anchor', version: 1, created_at: createdAt,
      what: 'Bitcoin block 0 coinbase public key, PEM (SubjectPublicKeyInfo, secp256k1)',
      files: Object.entries(PEM_HASHES).map(([file, sha]) => ({ file, sha256: sha })),
      threshold: THRESHOLD, signers: signerSet,
    },
  },
];
if (mainTip && botTip) {
  if (!/^[0-9a-f]{64}$/i.test(mainTip) || !/^[0-9a-f]{64}$/i.test(botTip)) fail('--main-tip and --bot-tip must be 64-hex block hashes');
  records.push({
    name: '3-join-block',
    body: {
      kind: 'paradox.join', version: 1, created_at: createdAt,
      main_chain: { name: 'chain-fingerprint', tip: mainTip.toLowerCase() },
      joined_chain: { name: 'paradox-bot-kit', tip: botTip.toLowerCase(), after_join: 'read-only' },
      threshold: THRESHOLD, signers: signerSet,
    },
  });
} else {
  console.log('note: join record skipped (pass --main-tip and --bot-tip to build it)');
}

// ---------- sign 3-of-3 and verify ----------
fs.mkdirSync(outDir, { recursive: true });
for (const r of records) {
  const bytes = Buffer.from(canon(r.body));
  const digest = sha256(bytes);
  const sigs = signers.map(s => ({
    signer: s.id, file: s.file,
    sig: crypto.sign(algFor(s.priv), bytes, s.priv).toString('base64'),
  }));
  // independent check with the public keys only
  const ok = sigs.filter(x => {
    const s = signers.find(k => k.id === x.signer);
    const pub = crypto.createPublicKey(s.pubPem);
    return crypto.verify(algFor(pub), bytes, pub, Buffer.from(x.sig, 'base64'));
  }).length;
  if (ok < THRESHOLD) fail(`${r.name}: only ${ok}/${THRESHOLD} signatures verified`);
  const out = { record: r.body, digest_sha256: digest, signatures: sigs, verified: `${ok}-of-${THRESHOLD}` };
  const file = path.join(outDir, r.name + '.json');
  fs.writeFileSync(file, JSON.stringify(out, null, 2) + '\n');
  console.log(`${r.name}: ${ok}-of-${THRESHOLD} verified  digest ${digest}  -> ${file}`);
}
console.log('done. Private keys were not written anywhere.');
