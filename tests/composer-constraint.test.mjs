import test from 'node:test';
import assert from 'node:assert/strict';
import { convertComposerConstraint, evaluateComposer, parseComposerVersion } from '../src/lib/composer-constraint.mjs';

test('変換できる形', () => {
  assert.equal(convertComposerConstraint('<12.68.0|>=13.0.0,<13.29.0').range, '<12.68.0 || >=13.0.0 <13.29.0');
  assert.equal(convertComposerConstraint('>= 1.0.0 < 2.0.0').range, '>=1.0.0 <2.0.0');
  assert.equal(convertComposerConstraint('=1.2.3 || v1.3.0').range, '1.2.3 || 1.3.0');
  assert.equal(convertComposerConstraint('<=2.4.1').ok, true);
});

test('D7: 変換できない形は ok:false（丸めない）', () => {
  for (const bad of ['~1.2', '^1.0', '1.2.*', '*', '1.0.0 - 2.0.0', '>=1.0.0-beta', '<1.2.3.5', '>=1.0@dev', '>=1.2', '!=1.0.0', '', 'dev-master']) {
    assert.equal(convertComposerConstraint(bad).ok, false, bad);
  }
});

test('境界値と判定', () => {
  const c = '<12.68.0|>=13.0.0,<13.29.0';
  assert.equal(evaluateComposer(c, '12.67.9').judgement, 'affected');
  assert.equal(evaluateComposer(c, '12.68.0').judgement, 'not_affected');
  assert.equal(evaluateComposer(c, '13.0.0').judgement, 'affected');
  assert.deepEqual(evaluateComposer(c, 'v13.28.0').fixed, ['13.29.0']);
  assert.equal(evaluateComposer(c, '13.29.0').judgement, 'not_affected');
});

test('D7: 導入版 1.2.3.4 と範囲 <1.2.3.5 は影響なしにならず needs_review', () => {
  assert.equal(evaluateComposer('<1.2.3.5', '1.2.3.4').judgement, 'needs_review');
  assert.equal(evaluateComposer('<1.2.3', '1.2.3.4').judgement, 'needs_review');
  assert.equal(evaluateComposer('<1.2.4', 'dev-main').judgement, 'needs_review');
  assert.equal(evaluateComposer('<1.2.4', '1.2').judgement, 'needs_review');
  assert.equal(evaluateComposer('~1.2', '1.2.5').judgement, 'needs_review');
  assert.equal(parseComposerVersion('1.2.3.4'), null);
});
