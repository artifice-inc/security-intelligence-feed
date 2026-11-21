import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicalJson, contentHash, sha256Hex } from '../src/lib/hash.mjs';
import { validate, assertValid, SchemaError } from '../src/lib/schema.mjs';
import { loadToolVersions } from '../src/lib/config.mjs';

test('canonicalJson はキー順に依存しない', () => {
  assert.equal(contentHash({ a: 1, b: [1, { d: 1, c: 2 }] }), contentHash({ b: [1, { c: 2, d: 1 }], a: 1 }));
  assert.equal(canonicalJson({ a: undefined, b: 1 }), '{"b":1}');
  assert.equal(sha256Hex('abc').length, 64);
});

test('スキーマ違反は SchemaError になる', () => {
  assert.equal(validate('health', {}).ok, false);
  assert.throws(() => assertValid('health', {}), SchemaError);
});

test('tool-versions のチェックサムは64桁の16進', () => {
  for (const asset of Object.values(loadToolVersions()['osv-scanner'].assets)) {
    assert.match(asset.sha256, /^[0-9a-f]{64}$/);
    assert.ok(asset.url.startsWith('https://github.com/google/osv-scanner/releases/download/'));
  }
});
