import test from 'node:test';
import assert from 'node:assert/strict';
import { reconcileIssues } from '../src/publish/issues-reconcile.mjs';
import { parseMarker } from '../src/publish/issue-body.mjs';
import { sentNoticeIds } from '../src/publish/notices.mjs';
import { FakeGitHub } from './helpers/fake-github.mjs';

const NOW = '2026-10-25T00:00:00Z';
const project = { project: 'demo', owners: ['alice'] };
let idCounter = 0;
const generateId = () => `id${++idCounter}`;

const itemOf = (key, overrides = {}) => ({
  advisory_key: key, aliases: [key], title: 'Example', locations: [{ lockfile: 'package-lock.json', package: 'pkg', ecosystem: 'npm', installed_version: '1.0.0', last_confirmed_at: NOW, last_confirmed_provenance: {} }],
  fixed_versions: ['1.0.1'], source_urls: ['https://osv.dev/vulnerability/X'], judgement: 'affected', priority: 'P1', evidence: 'ev', kev: false, issue_number: null,
  first_detected_at: NOW, last_confirmed_at: NOW, last_confirmed_provenance: {}, ...overrides,
});
const findingsOf = (items, scan_status = 'complete') => new Map([['demo', { project: 'demo', scan_status, items }]]);
const run = (api, items, options = {}) => reconcileIssues({
  api, projects: [project], findingsByProject: findingsOf(items, options.scanStatus), now: options.now ?? NOW, generateId, isWithdrawn: options.isWithdrawn,
});
const only = (api) => [...api.issues.values()][0];
// 誤クローズ（ラベルなしで人がクローズ）→ 次の実行で再オープンと misclose 通知が発生する状態にする
const misclosed = async () => { const api = new FakeGitHub(); await run(api, [itemOf('CVE-1')]); api.humanClose(1); return api; };
const again = (api, overrides) => run(api, [itemOf('CVE-1', overrides)]);

// ---- D1 / D8 -------------------------------------------------------------------------------

test('D1: 起票の後に push が失敗した状態（issues.json も findings もない）で次回を実行しても重複しない', async () => {
  const api = new FakeGitHub();
  await run(api, [itemOf('CVE-1')]);
  // 前回の issue_number が findings に残っていない状態を再現: 入力の item.issue_number は常に null
  await run(api, [itemOf('CVE-1', { issue_number: null })]);
  assert.equal(api.issues.size, 1);
});

test('D1: fixed-in-repo の付与だけが失敗しても、次回の実行で再試行されて成功する', async () => {
  const api = new FakeGitHub();
  await run(api, [itemOf('CVE-1')]);
  api.failNext('updateIssue', ([, patch]) => Boolean(patch.labels), 1);
  const failed = await run(api, []);
  assert.equal(failed.errors.length, 1);
  assert.ok(!only(api).labels.includes('fixed-in-repo'));
  const retried = await run(api, []);
  assert.equal(retried.errors.length, 0);
  assert.ok(only(api).labels.includes('fixed-in-repo'));
  assert.equal((api.comments.get(1) ?? []).length, 0);
});

test('D8: 状態の変更は成功しコメントだけ失敗（誤クローズの再オープン）→ 次回に1回だけ投稿され、以後は増えない', async () => {
  const api = await misclosed();
  api.failNext('createComment', () => true, 1);
  const first = await again(api);
  assert.equal(first.errors.length, 1);
  assert.equal(only(api).state, 'open');
  assert.equal(parseMarker(only(api).body).pending.length, 1);
  assert.equal((api.comments.get(1) ?? []).length, 0);
  const second = await again(api);
  assert.equal(second.errors.length, 0);
  assert.equal(api.comments.get(1).length, 1);
  assert.equal(parseMarker(only(api).body).pending.length, 0);
  api.resetWrites();
  await again(api);
  await again(api);
  assert.equal(api.writeCount, 0);
  assert.equal(api.comments.get(1).length, 1);
});

test('T-A: マーカーに fixed の pending が残る既存 Issue は、次回に1回だけ投稿され、以後は増えない', async () => {
  const api = new FakeGitHub();
  await run(api, [itemOf('CVE-1')]);
  const issue = only(api);
  const marker = parseMarker(issue.body);
  const legacy = { ...marker, pending: [{ id: 'fixed-legacy', kind: 'fixed', reason: '' }] };
  issue.body = `${issue.body.trimEnd().split('\n').slice(0, -1).join('\n')}\n<!-- si:${JSON.stringify(legacy)} -->`;
  await run(api, [itemOf('CVE-1')]);
  assert.equal(api.comments.get(1).length, 1);
  assert.match(api.comments.get(1)[0].body, /本番への反映/);
  assert.equal(parseMarker(only(api).body).pending.length, 0);
  api.resetWrites();
  await run(api, [itemOf('CVE-1')]);
  assert.equal(api.writeCount, 0);
  assert.equal(api.comments.get(1).length, 1);
});

test('D8: 再オープン・risk-accepted の除去は成功し、理由のコメントだけ失敗 → 理由が復元されて1回だけ投稿', async () => {
  const api = new FakeGitHub();
  await run(api, [itemOf('CVE-1', { priority: 'P2' })]);
  api.humanLabel(1, 'risk-accepted', '2026-10-01T00:00:00Z');
  api.humanClose(1);
  api.failNext('createComment', () => true, 1);
  await run(api, [itemOf('CVE-1', { priority: 'P0', kev: true })], { now: '2026-11-01T00:00:00Z' });
  assert.equal(only(api).state, 'open');
  assert.ok(!only(api).labels.includes('risk-accepted'));
  assert.match(parseMarker(only(api).body).pending[0].reason, /kev/);
  await run(api, [itemOf('CVE-1', { priority: 'P0', kev: true })], { now: '2026-11-01T01:00:00Z' });
  assert.equal(api.comments.get(1).length, 1);
  assert.match(api.comments.get(1)[0].body, /KEV/);
  api.resetWrites();
  await run(api, [itemOf('CVE-1', { priority: 'P0', kev: true })], { now: '2026-11-01T02:00:00Z' });
  assert.equal(api.writeCount, 0);
});

test('D8: 人が書いた si-notice マーカーのコメントは送信済みとみなさない', async () => {
  const api = await misclosed();
  api.failNext('createComment', () => true, 1);
  await again(api);
  const pendingId = parseMarker(only(api).body).pending[0].id;
  api.humanComment(1, `偽装 <!-- si-notice:${pendingId} -->`, 'attacker');
  assert.equal(sentNoticeIds(api.comments.get(1), api.botLogin).size, 0);
  await again(api);
  assert.equal(api.comments.get(1).filter((c) => c.author === api.botLogin).length, 1);
});

test('D8（第3.1版）: コメントは成功し pending を外す PATCH だけ失敗 → 次回はコメントを重複せず pending を外すだけ。その次は0件', async () => {
  const api = await misclosed();
  // 1回目の updateIssue（再オープン+pending）は成功、2回目（pending を外す）を失敗させる
  let updates = 0;
  api.failNext('updateIssue', () => { updates += 1; return updates === 2; }, 1);
  const first = await again(api);
  assert.equal(first.errors.length, 1);
  assert.equal(api.comments.get(1).length, 1);
  assert.equal(parseMarker(only(api).body).pending.length, 1);
  api.resetWrites();
  await again(api);
  assert.equal(api.comments.get(1).length, 1, 'コメントは重複しない');
  assert.deepEqual(api.writes.map((w) => w.op), ['updateIssue']);
  assert.equal(parseMarker(only(api).body).pending.length, 0);
  api.resetWrites();
  await again(api);
  assert.equal(api.writeCount, 0);
});

test('D8: 未送信の pending がある Issue で本文を生成し直しても pending が消えない', async () => {
  const api = await misclosed();
  api.failNext('createComment', () => true, 1);
  await again(api);
  const before = parseMarker(only(api).body).pending;
  assert.equal(before.length, 1);
  // コメント投稿を失敗させたまま、本文が再生成される
  api.failNext('createComment', () => true, 5);
  await again(api, { fixed_versions: ['9.9.9'] });
  assert.match(only(api).body, /9\.9\.9/);
  const after = parseMarker(only(api).body).pending;
  assert.ok(after.some((p) => p.id === before[0].id), '前回の pending は引き継がれる');
});

test('Issue の一覧取得に失敗した回は何も操作せず、エラーを返す', async () => {
  const api = new FakeGitHub();
  api.failNext('listIssues', () => true, 3);
  const result = await run(api, [itemOf('CVE-1')]);
  assert.equal(api.issues.size, 0);
  assert.ok(result.errors.length > 0);
  assert.equal(result.snapshot, null);
});
