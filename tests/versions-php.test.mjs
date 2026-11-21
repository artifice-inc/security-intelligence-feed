import test from 'node:test';
import assert from 'node:assert/strict';
import { comparePhp, parsePhpRange, isPhpBranchAffected, parsePhpVersion } from '../src/lib/versions-php.mjs';

const [range] = parsePhpRange('< 8.2.35', null);
const branch = (b, fixed) => ({ type: 'PHP_BRANCH', branch: b, fixed });

test('境界値: 8.2.34 は影響あり、8.2.35 は影響なし', () => {
  assert.equal(isPhpBranchAffected(range, '8.2.34'), true);
  assert.equal(isPhpBranchAffected(range, '8.2.35'), false);
  assert.equal(isPhpBranchAffected(range, '8.2.9'), true);
});

test('ブランチ違いは影響なし', () => {
  assert.equal(isPhpBranchAffected(range, '8.3.1'), false);
  assert.equal(isPhpBranchAffected(range, '8.1.34'), false);
});

test('版が解釈できなければ null（needs_review 側）', () => {
  assert.equal(isPhpBranchAffected(range, '8.2'), null);
  assert.equal(isPhpBranchAffected(range, '8.2.35-rc1'), null);
  assert.equal(parsePhpVersion('8.2.0.1'), null);
});

test('数値比較であり文字列比較ではない', () => {
  assert.equal(comparePhp('8.2.10', '8.2.9'), 1);
  assert.equal(comparePhp('8.2.9', '8.2.9'), 0);
});

test('範囲の表記揺れ: 空白の有無は許し、patched が範囲の内側なら null', () => {
  assert.deepEqual(parsePhpRange('<8.2.35', '8.2.35'), [branch('8.2', '8.2.35')]);
  assert.equal(parsePhpRange('<8.2.35', '8.2.34'), null);
  assert.equal(parsePhpRange('<= 8.2.35', null), null);
  assert.equal(parsePhpRange('<= 8.2.35', '8.2.35'), null);
});

// 以下は php-src の GHSA に実際にある表記
test('上限が未リリース版で patched が次の版: patched を修正版にする', () => {
  assert.deepEqual(parsePhpRange('< 8.3.5', '8.3.6'), [branch('8.3', '8.3.6')]);
  assert.deepEqual(parsePhpRange('< 8.1.28', ' 8.1.28'), [branch('8.1', '8.1.28')]);
});

test('<= と下限付きの組み合わせ', () => {
  assert.deepEqual(parsePhpRange('<=8.0.27', '8.0.28'), [branch('8.0', '8.0.28')]);
  assert.deepEqual(parsePhpRange('>=8.2.0, <=8.2.2', '8.2.3'), [branch('8.2', '8.2.3')]);
  assert.deepEqual(parsePhpRange('> 8.1.11, < 8.1.28', '8.1.28'), [branch('8.1', '8.1.28')]);
});

test('複数ブランチの列挙と、修正版にだけ出るブランチ', () => {
  // 7.3・7.4・8.0 は修正版がなく上限も含む側なので、そのブランチだけ UNPARSED
  const raw = '7.3.27 - 7.3.33, 7.4.15 - 7.4.33, 8.0.2 - 8.0.30, 8.1.0 - 8.1.28, 8.2.0 - 8.2.19, 8.3.0 - 8.3.7';
  const unparsed = (b) => ({ type: 'UNPARSED', branch: b, raw });
  assert.deepEqual(
    parsePhpRange(raw, '8.1.29, 8.2.20, 8.3.8.'),
    [unparsed('7.3'), unparsed('7.4'), unparsed('8.0'), branch('8.1', '8.1.29'), branch('8.2', '8.2.20'), branch('8.3', '8.3.8')],
  );
  assert.deepEqual(
    parsePhpRange('8.1.0 - 8.1.28, 8.2.0 - 8.2.19, 8.3.0 - 8.3.7', '8.1.29, 8.2.20, 8.3.8.'),
    [branch('8.1', '8.1.29'), branch('8.2', '8.2.20'), branch('8.3', '8.3.8')],
  );
  assert.deepEqual(parsePhpRange('8.3.6', '8.1.29, 8.2.20, 8.3.8'), [branch('8.1', '8.1.29'), branch('8.2', '8.2.20'), branch('8.3', '8.3.8')]);
});

test('決められない表記は null のまま（needs_review 側）', () => {
  assert.equal(parsePhpRange('8.2.12', ''), null); // CVE-2024-2408。再現環境の版で、範囲ではない
  assert.equal(parsePhpRange('>= 8.2.0', null), null);
  assert.equal(parsePhpRange('< 8.2.10, < 8.2.20', null), null);
  assert.equal(parsePhpRange('< 8.2.20', '8.2.20, 8.2.21'), null);
  assert.equal(parsePhpRange('< 8.2.20', 'next release'), null);
});
