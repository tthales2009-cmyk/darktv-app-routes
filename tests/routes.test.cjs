'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const crypto = require('node:crypto');
const vm = require('node:vm');
const { verifyRoutes, verifyDestination } = require('../scripts/verify-routes.cjs');
const current = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'darktv-routes.json'), 'utf8'));

test('current public route document has a valid signature and HTTPS destinations', () => {
  assert.doesNotThrow(() => verifyRoutes(current));
});

test('tampered payload, missing signature and unexpected algorithm are rejected', () => {
  const changed = structuredClone(current);
  changed.payload.version++;
  assert.throws(() => verifyRoutes(changed), /signature/i);
  assert.throws(() => verifyRoutes({ ...current, signature: '' }), /signature/i);
  assert.throws(() => verifyRoutes({ ...current, algorithm: 'none' }), /algorithm/i);
});

test('malformed documents are rejected without emitting their contents', () => {
  for (const document of [null, {}, { algorithm: 'RS256', payload: {}, signature: 'invalid' }]) {
    assert.throws(() => verifyRoutes(document));
  }
});

test('destination validation rejects HTTP and credential-bearing URLs', () => {
  for (const url of ['http://example.test', 'https://fixture:fixture@routes.example.test',
    'https://example.test/?token=fixture', 'https://example.test/?api_key=fixture']) {
    assert.throws(() => verifyDestination(url));
  }
  assert.doesNotThrow(() => verifyDestination('https://example.test/config.json'));
  assert.doesNotThrow(() => verifyDestination(''));
});

test('even correctly signed payloads must contain all client-required primary routes', () => {
  const pair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const moduleFixture = { exports: {} };
  const source = fs.readFileSync(path.join(__dirname, '..', 'scripts/verify-routes.cjs'), 'utf8');
  const sandboxRequire = name => name === 'node:fs'
    ? { readFileSync: () => pair.publicKey.export({ type: 'spki', format: 'pem' }) }
    : require(name);
  vm.runInNewContext(source, { require: sandboxRequire, module: moduleFixture, Buffer, URL, __dirname });
  const verify = moduleFixture.exports.verifyRoutes;
  const sign = payload => ({ algorithm: 'RS256', payload,
    signature: crypto.sign('RSA-SHA256', Buffer.from(JSON.stringify(payload)), pair.privateKey).toString('base64') });
  const valid = { version: 4, updatedAt: 1786228978,
    api: { primary: 'https://api.example.test' }, live: { primary: 'https://media.example.test' },
    vod: { primary: 'https://media.example.test' } };
  assert.doesNotThrow(() => verify(sign(valid)));
  for (const kind of ['api', 'live', 'vod']) {
    for (const value of [undefined, {}, { primary: '' }]) {
      const invalid = structuredClone(valid);
      invalid[kind] = value;
      assert.throws(() => verify(sign(invalid)), /primary/i);
    }
  }
});
