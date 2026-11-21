import test from 'node:test';
import assert from 'node:assert/strict';
import { buildCentralIssues } from '../src/local/check-summary.mjs';

const localScan = { complete: true, reasons: [] };
const issue = (n, labels, extra = {}) => ({ issue_number: n, project: 'demo', aliases: [`CVE-${n}`], state: 'open', labels, ...extra });
const build = (issuesFile) => buildCentralIssues({ issuesFile, projectName: 'demo', localScan, aliasSets: [] });

test('取り下げ付きの P1 は advisory_withdrawn に入り、open.P1 にも数える', () => {
  const result = build([issue(1, ['P1', 'advisory-withdrawn'])]);
  assert.deepEqual(result.advisory_withdrawn, [{ issue_number: 1, aliases: ['CVE-1'] }]);
  assert.equal(result.open.P1, 1);
});

test('fixed-in-repo と取り下げの両方 → fixed_in_repo だけに入る', () => {
  const result = build([issue(2, ['fixed-in-repo', 'advisory-withdrawn'])]);
  assert.deepEqual(result.fixed_in_repo.map((i) => i.issue_number), [2]);
  assert.deepEqual(result.advisory_withdrawn, []);
});

test('superseded_by が数値で取り下げ付き → superseded だけに入る', () => {
  const result = build([issue(3, ['advisory-withdrawn'], { superseded_by: 9 })]);
  assert.deepEqual(result.superseded.map((i) => i.issue_number), [3]);
  assert.deepEqual(result.advisory_withdrawn, []);
});

test('取り下げのラベルがなければ空配列で、open と resolved_locally は従来どおり', () => {
  const result = build([issue(4, ['P2'])]);
  assert.deepEqual(result.advisory_withdrawn, []);
  assert.deepEqual(result.open, { P0: 0, P1: 0, P2: 1 });
  assert.deepEqual(result.resolved_locally.map((i) => i.issue_number), [4]);
});

test('issuesFile が null なら central_issues は null', () => {
  assert.equal(build(null), null);
});
