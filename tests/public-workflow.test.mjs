import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import YAML from 'yaml';
import { ROOT_DIR, loadSchedule } from '../src/lib/config.mjs';
import { toUtcCron } from '../src/lib/schedule.mjs';

// 公開側では .github/workflows/、このリポジトリでは templates/public/ の下を検査する
const candidates = [
  '.github/workflows/collect-feed.yml',
  'templates/public/.github/workflows/collect-feed.yml',
];
const file = candidates.map((f) => path.join(ROOT_DIR, f)).find(existsSync);
assert.ok(file, 'collect-feed.yml が見つかりません');
const text = readFileSync(file, 'utf8');
const workflow = YAML.parse(text);
const steps = Object.values(workflow.jobs).flatMap((job) => job.steps);

test('concurrency は固定の group で、先の実行を中断しない', () => {
  assert.deepEqual(workflow.concurrency, { group: 'feed-collect', 'cancel-in-progress': false });
});

test('feed の取り出しがジョブの中にあり、main のチェックアウトより後ろにある', () => {
  const checkouts = steps.filter((s) => s.uses?.startsWith('actions/checkout@'));
  const feedIndex = steps.findIndex((s) => s.uses?.startsWith('actions/checkout@') && s.with?.ref === 'feed');
  assert.ok(feedIndex > steps.indexOf(checkouts[0]));
  assert.equal(steps[feedIndex].with.path, 'feed-root');
  assert.ok(steps.some((s) => /run-collect\.mjs --feed-root feed-root/.test(s.run ?? '')));
});

test('外部の Action はコミット SHA で固定されている', () => {
  assert.ok(steps.some((s) => s.uses));
  for (const step of steps.filter((s) => s.uses)) assert.match(step.uses, /@[0-9a-f]{40}$/, step.uses);
});

test('権限: 最上位は {}、ジョブは contents: write だけ（issues なし）', () => {
  assert.deepEqual(workflow.permissions, {});
  for (const job of Object.values(workflow.jobs)) assert.deepEqual(job.permissions, { contents: 'write' });
  assert.ok(!/issues\s*:/.test(text.replace(/#.*$/gm, '')));
});

test('トークンは run-collect のステップだけに渡す', () => {
  assert.equal(workflow.env, undefined);
  for (const job of Object.values(workflow.jobs)) assert.equal(job.env, undefined);
  const withToken = steps.filter((s) => s.env && 'GITHUB_TOKEN' in s.env);
  assert.equal(withToken.length, 1);
  assert.match(withToken[0].run, /run-collect\.mjs/);
  assert.equal(withToken[0].env.GITHUB_TOKEN, '${{ github.token }}');
  assert.ok(!steps.some((s) => s.with && JSON.stringify(s.with).includes('token')));
});

test('cron が config/schedule.json を UTC に変換した値と一致する', () => {
  const [, minute, hours] = /cron: "(\d+) ([\d,]+) \* \* \*"/.exec(text);
  const expected = toUtcCron(loadSchedule(), new Date('2026-10-24T00:00:00Z'));
  assert.equal(Number(minute), expected.minute);
  assert.deepEqual(hours.split(',').map(Number).sort((a, b) => a - b), expected.hours);
});
