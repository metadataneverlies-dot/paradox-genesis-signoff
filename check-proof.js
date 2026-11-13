#!/usr/bin/env node
'use strict';
// Check your signed message before running finalize.js.
// Usage: node check-proof.js <base64 signature>
const { verifyMessage } = require('./btcmsg');
const ADDRESS = 'bc1qx7avk4smhrvpnjpm4p8ukzp6xleguuc7z9fhz3';
const MESSAGE = 'PARADOX genesis: I made Bitcoin transaction d86bdcbcac4fc73ddc6a7383d85ad902e09333ba9a26f67a41b5908f33757476';
const sig = process.argv[2];
if (!sig) {
  console.log('Sign this exact text with address ' + ADDRESS + ' in your wallet:\n\n' + MESSAGE + '\n\nthen run: node check-proof.js <signature>');
  process.exit(1);
}
const r = verifyMessage(ADDRESS, MESSAGE, sig);
console.log(r.ok ? 'VALID: signed by the key behind ' + ADDRESS : 'INVALID: ' + r.why);
process.exit(r.ok ? 0 : 1);
