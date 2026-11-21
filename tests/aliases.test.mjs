import test from 'node:test';
import assert from 'node:assert/strict';
import { connectedComponents, canonicalKey, splitAliases } from '../src/lib/aliases.mjs';

test('別名が1つでも共通すれば同じ連結成分になる', () => {
  const groups = connectedComponents([['GHSA-a', 'CVE-1'], ['CVE-1', 'PKSA-x'], ['GHSA-z'], ['CVE-9']]);
  assert.equal(groups.length, 3);
  assert.deepEqual(groups.find((g) => g.indexes.includes(0)).ids, ['CVE-1', 'GHSA-a', 'PKSA-x']);
  assert.deepEqual(groups.find((g) => g.indexes.includes(0)).indexes, [0, 1]);
});

test('推移的に連結される（A-B, C-D, B-C）', () => {
  const groups = connectedComponents([['A', 'B'], ['C', 'D'], ['B', 'C']]);
  assert.equal(groups.length, 1);
});

test('正規キーは CVE → GHSA → PKSA → NODE-CORE の順で、ファイル名に安全', () => {
  assert.equal(canonicalKey(['GHSA-a', 'CVE-2026-1', 'PKSA-x']), 'CVE-2026-1');
  assert.equal(canonicalKey(['PKSA-x', 'GHSA-a']), 'GHSA-a');
  assert.equal(canonicalKey(['NODE-CORE-5']), 'NODE-CORE-5');
  assert.equal(canonicalKey(['weird/id:1']), 'weird-id-1');
});

test('別名の分類', () => {
  assert.deepEqual(splitAliases(['PKSA-x', 'CVE-1', 'GHSA-a', 'CVE-1']), { cve: ['CVE-1'], ghsa: ['GHSA-a'], other: ['PKSA-x'] });
});
