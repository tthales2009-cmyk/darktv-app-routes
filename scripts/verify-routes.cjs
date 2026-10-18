'use strict';
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

function verifyDestination(value) {
  if (value === '') return;
  const url = new URL(value);
  assert.equal(url.protocol, 'https:', 'Route destination must use HTTPS');
  assert(!url.username && !url.password, 'Route destination must not contain credentials');
  assert(![...url.searchParams.keys()].some(key => /password|token|secret|username|api[_-]?key/i.test(key)),
    'Route destination must not contain credential parameters');
}

function verifyRoutes(envelope) {
  assert.equal(envelope?.algorithm, 'RS256', 'Invalid route signing algorithm');
  assert(envelope.payload && typeof envelope.payload === 'object', 'Missing route payload');
  assert(typeof envelope.signature === 'string' && envelope.signature.length > 0, 'Missing route signature');
  const key = fs.readFileSync(path.join(__dirname, '..', 'routes-public-key.pem'));
  assert(crypto.verify('RSA-SHA256', Buffer.from(JSON.stringify(envelope.payload)), key,
    Buffer.from(envelope.signature, 'base64')), 'Invalid route signature');
  assert(Number.isSafeInteger(envelope.payload.version) && envelope.payload.version > 0, 'Invalid route version');
  assert(Number.isSafeInteger(envelope.payload.updatedAt) && envelope.payload.updatedAt > 0, 'Invalid route timestamp');
  for (const kind of ['api', 'live', 'vod']) {
    const primary = envelope.payload[kind]?.primary;
    assert(typeof primary === 'string' && primary.trim(), 'Missing required primary route');
    verifyDestination(primary);
  }
  function walk(value) {
    if (typeof value === 'string') verifyDestination(value);
    else if (value && typeof value === 'object') Object.values(value).forEach(walk);
  }
  walk(envelope.payload);
}

module.exports = { verifyRoutes, verifyDestination };
if (require.main === module) {
  verifyRoutes(JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'darktv-routes.json'), 'utf8')));
  console.log('Signed route document verified; destinations use HTTPS without credentials.');
}
