'use strict';
// Verify a Bitcoin "signed message" (BIP-137 compact signature, as made by
// Electrum, Sparrow, Bitcoin Core signmessage and most wallets) against a
// native SegWit (bc1q...) or legacy (1...) address. Pure Node, no packages.
const crypto = require('crypto');

const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const G = [0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
           0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n];
const mod = (a, m = P) => ((a % m) + m) % m;
function inv(a, m = P) { let [x, y, r0, r1] = [1n, 0n, mod(a, m), m];
  while (r1) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [x, y] = [y, x - q * y]; } return mod(x, m); }
function add(A, B) {
  if (!A) return B; if (!B) return A;
  if (A[0] === B[0] && mod(A[1] + B[1]) === 0n) return null;
  const l = A[0] === B[0] && A[1] === B[1] ? mod(3n * A[0] * A[0] * inv(2n * A[1])) : mod((B[1] - A[1]) * inv(B[0] - A[0]));
  const x = mod(l * l - A[0] - B[0]); return [x, mod(l * (A[0] - x) - A[1])];
}
function mul(k, A) { let R = null; while (k > 0n) { if (k & 1n) R = add(R, A); A = add(A, A); k >>= 1n; } return R; }
function powmod(b, e, m) { let r = 1n; b = mod(b, m); while (e) { if (e & 1n) r = r * b % m; b = b * b % m; e >>= 1n; } return r; }
const big = b => BigInt('0x' + (Buffer.from(b).toString('hex') || '0'));
const sha256 = b => crypto.createHash('sha256').update(b).digest();
const hash160 = b => crypto.createHash('ripemd160').update(sha256(b)).digest();

function varint(n) { if (n < 0xfd) return Buffer.from([n]); const b = Buffer.alloc(3); b[0] = 0xfd; b.writeUInt16LE(n, 1); return b; }
function messageHash(msg) {
  const m = Buffer.from(msg, 'utf8');
  const pre = Buffer.from('\x18Bitcoin Signed Message:\n', 'latin1');
  return sha256(sha256(Buffer.concat([pre, varint(m.length), m])));
}

// bech32 decode (witness v0 only) and base58check decode
const CH = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
function polymod(v) { const g = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]; let c = 1;
  for (const x of v) { const t = c >> 25; c = ((c & 0x1ffffff) << 5) ^ x; for (let i = 0; i < 5; i++) if ((t >> i) & 1) c ^= g[i]; } return c; }
function decodeAddress(addr) {
  const a = addr.toLowerCase();
  if (a.startsWith('bc1q')) {
    const data = [...a.slice(3)].map(c => CH.indexOf(c));
    if (data.includes(-1)) throw new Error('bad bech32 character');
    const hrp = [...'bc'].map(c => c.charCodeAt(0) >> 5).concat([0], [...'bc'].map(c => c.charCodeAt(0) & 31));
    if (polymod(hrp.concat(data)) !== 1) throw new Error('bad bech32 checksum');
    let acc = 0, bits = 0; const out = [];
    for (const v of data.slice(1, -6)) { acc = (acc << 5) | v; bits += 5; while (bits >= 8) { bits -= 8; out.push((acc >> bits) & 255); } }
    if (out.length !== 20) throw new Error('not a P2WPKH address');
    return { type: 'p2wpkh', hash: Buffer.from(out) };
  }
  const A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let n = 0n; for (const c of addr) { const i = A.indexOf(c); if (i < 0) throw new Error('bad base58'); n = n * 58n + BigInt(i); }
  let hex = n.toString(16); if (hex.length % 2) hex = '0' + hex;
  const b = Buffer.concat([Buffer.alloc(addr.match(/^1*/)[0].length), Buffer.from(hex, 'hex')]);
  if (!sha256(sha256(b.slice(0, -4))).slice(0, 4).equals(b.slice(-4))) throw new Error('bad base58 checksum');
  if (b[0] !== 0x00) throw new Error('only P2PKH (1...) or P2WPKH (bc1q...) supported');
  return { type: 'p2pkh', hash: b.slice(1, 21) };
}

// Recover the public key from a 65-byte compact signature, then compare hash160.
function verifyMessage(address, message, sigBase64) {
  const sig = Buffer.from(sigBase64, 'base64');
  if (sig.length !== 65) return { ok: false, why: 'signature is not 65 bytes' };
  const header = sig[0];
  if (header < 27 || header > 42) return { ok: false, why: 'bad signature header' };
  const recid = (header - 27) & 3;
  const r = big(sig.slice(1, 33)), s = big(sig.slice(33));
  if (!r || r >= N || !s || s >= N) return { ok: false, why: 'r or s out of range' };
  const x = r + BigInt(recid >> 1) * N; if (x >= P) return { ok: false, why: 'bad recovery id' };
  let y = powmod(mod(x * x * x + 7n), (P + 1n) / 4n, P);
  if (mod(y * y) !== mod(x * x * x + 7n)) return { ok: false, why: 'r is not on the curve' };
  if ((y & 1n) !== BigInt(recid & 1)) y = P - y;
  const e = big(messageHash(message));
  const ri = inv(r, N);
  const Q = add(mul(mod(s * ri, N), [x, y]), mul(mod(-e * ri, N), G));
  if (!Q) return { ok: false, why: 'recovered point at infinity' };
  const X = Buffer.from(Q[0].toString(16).padStart(64, '0'), 'hex');
  const pub = Buffer.concat([Buffer.from([Q[1] & 1n ? 3 : 2]), X]);
  let want; try { want = decodeAddress(address); } catch (err) { return { ok: false, why: err.message }; }
  const ok = hash160(pub).equals(want.hash);
  return { ok, pubkey: pub.toString('hex'), why: ok ? '' : 'signature is valid but from a different key than the address' };
}

module.exports = { verifyMessage, messageHash };
