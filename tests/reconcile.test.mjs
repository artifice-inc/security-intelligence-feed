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
  api, projects: [project], findingsByProject: findingsOf(items, options.scanStatus), now: options.now ?? NOW, generateId, isWithdrawnAliases: options.isWithdrawn,
});
const only = (api) => [...api.issues.values()][0];

test('新規: P1 は起票され、P3 は起票されない。タイトル・ラベル・assignee・マーカー', async () => {
  const api = new FakeGitHub();
  const result = await run(api, [itemOf('CVE-1'), itemOf('RUNTIME-UNKNOWN-php', { judgement: 'needs_review', priority: 'P3' })]);
  assert.equal(api.issues.size, 1);
  const issue = only(api);
  assert.equal(issue.title, '[P1][demo] CVE-1 pkg');
  assert.deepEqual(issue.labels.sort(), ['P1', 'project:demo', 'security-finding']);
  assert.deepEqual(issue.assignees, ['alice']);
  assert.equal(parseMarker(issue.body).project, 'demo');
  assert.equal(result.issueNumbers.get('demo').get('CVE-1'), 1);
  assert.deepEqual(result.snapshot.map((s) => s.issue_number), [1]);
  assert.equal(result.errors.length, 0);
});

test('冪等性: 同じ入力で2回目は Issue への書き込みが0件', async () => {
  const api = new FakeGitHub();
  await run(api, [itemOf('CVE-1')]);
  api.resetWrites();
  const second = await run(api, [itemOf('CVE-1')]);
  assert.equal(api.writeCount, 0);
  assert.equal(second.issueNumbers.get('demo').get('CVE-1'), 1);
});

test('open + 項目あり: 本文・優先度ラベル・タイトルを更新し、別名は和集合になる', async () => {
  const api = new FakeGitHub();
  await run(api, [itemOf('GHSA-x', { aliases: ['GHSA-x'], priority: 'P2' })]);
  await run(api, [itemOf('CVE-1', { aliases: ['CVE-1', 'GHSA-x'], priority: 'P1', fixed_versions: ['2.0.0'] })]);
  assert.equal(api.issues.size, 1, '別名が共通するので重複して起票されない（試験5）');
  const issue = only(api);
  assert.equal(issue.title, '[P1][demo] CVE-1 pkg');
  assert.ok(issue.labels.includes('P1') && !issue.labels.includes('P2'));
  assert.deepEqual(parseMarker(issue.body).aliases, ['CVE-1', 'GHSA-x']);
  assert.match(issue.body, /2\.0\.0/);
});

test('解消: open は fixed-in-repo を付けるだけでコメントしない。2回目は何もしない', async () => {
  const api = new FakeGitHub();
  await run(api, [itemOf('CVE-1')]);
  await run(api, []);
  const issue = only(api);
  assert.ok(issue.labels.includes('fixed-in-repo'));
  assert.equal(issue.state, 'open', '自動でクローズしない');
  assert.equal((api.comments.get(1) ?? []).length, 0, 'コメントしない（U1）');
  assert.equal(parseMarker(issue.body).pending.length, 0, '正常に終われば pending は残らない');
  api.resetWrites();
  await run(api, []);
  assert.equal(api.writeCount, 0);
});

test('closed + fixed-in-repo なしで解消: ラベルだけ付け、コメントはしない', async () => {
  const api = new FakeGitHub();
  await run(api, [itemOf('CVE-1')]);
  api.humanClose(1);
  await run(api, []);
  assert.ok(only(api).labels.includes('fixed-in-repo'));
  assert.equal((api.comments.get(1) ?? []).length, 0);
});

test('partial / failed の案件では、どの Issue も解消と判定しない（試験2/3）', async () => {
  for (const scanStatus of ['partial', 'failed']) {
    const api = new FakeGitHub();
    await run(api, [itemOf('CVE-1')]);
    api.resetWrites();
    await run(api, [], { scanStatus });
    assert.equal(api.writeCount, 0);
    assert.ok(!only(api).labels.includes('fixed-in-repo'));
  }
});

test('再発: fixed-in-repo 後に再検出すると、ラベルを外して「再発」とコメント。closed なら再オープン（試験7）', async () => {
  const api = new FakeGitHub();
  await run(api, [itemOf('CVE-1')]);
  await run(api, []);
  await run(api, [itemOf('CVE-1')]);
  assert.ok(!only(api).labels.includes('fixed-in-repo'));
  assert.match(api.comments.get(1).at(-1).body, /再発/);
  await run(api, []);
  api.humanClose(1);
  await run(api, [itemOf('CVE-1')]);
  assert.equal(only(api).state, 'open');
  assert.ok(!only(api).labels.includes('fixed-in-repo'));
  assert.match(api.comments.get(1).at(-1).body, /再発/);
});

test('D2: ラベルなしでクローズされたら誤クローズとして再オープンする', async () => {
  const api = new FakeGitHub();
  await run(api, [itemOf('CVE-1')]);
  api.humanClose(1);
  await run(api, [itemOf('CVE-1')]);
  assert.equal(only(api).state, 'open');
  assert.match(api.comments.get(1).at(-1).body, /risk-accepted/);
});

test('D2: risk-accepted でクローズ → 期限内は再オープンされない（閉じた Issue の P ラベルも変えない）', async () => {
  const api = new FakeGitHub();
  await run(api, [itemOf('CVE-1', { priority: 'P2' })]);
  api.humanLabel(1, 'risk-accepted', '2026-10-01T00:00:00Z');
  api.humanClose(1);
  api.resetWrites();
  const result = await run(api, [itemOf('CVE-1', { priority: 'P2' })], { now: '2026-12-20T00:00:00Z' });
  assert.equal(only(api).state, 'closed');
  assert.equal(api.writeCount, 0);
  assert.equal(result.digestInfo.riskAccepted.length, 1);
  assert.equal(result.digestInfo.riskAccepted[0].accepted_at, '2026-10-01T00:00:00Z');
});

test('D2: 期限切れ（90日超）・KEV 掲載・優先度の上昇のそれぞれで再オープンし、理由をコメントする', async () => {
  const cases = [
    ['期限', { priority: 'P2' }, '2027-01-05T00:00:00Z', /期限/],
    ['KEV', { priority: 'P0', kev: true }, '2026-11-01T00:00:00Z', /KEV/],
    ['優先度', { priority: 'P1' }, '2026-11-01T00:00:00Z', /優先度/],
  ];
  for (const [, changed, now, pattern] of cases) {
    const api = new FakeGitHub();
    await run(api, [itemOf('CVE-1', { priority: 'P2' })]);
    api.humanLabel(1, 'risk-accepted', '2026-10-01T00:00:00Z');
    api.humanClose(1);
    await run(api, [itemOf('CVE-1', changed)], { now });
    const issue = only(api);
    assert.equal(issue.state, 'open');
    assert.ok(!issue.labels.includes('risk-accepted'));
    assert.match(api.comments.get(1).at(-1).body, pattern);
    assert.match(api.comments.get(1).at(-1).body, /@alice/);
  }
});

test('D2: risk-accepted の付与日時を取得できなければ安全側で再オープンする', async () => {
  const api = new FakeGitHub();
  await run(api, [itemOf('CVE-1')]);
  api.humanLabel(1, 'risk-accepted', '2026-10-24T00:00:00Z');
  api.humanClose(1);
  api.failNext('listIssueEvents', () => true, 5);
  await run(api, [itemOf('CVE-1')]);
  assert.equal(only(api).state, 'open');
});

test('取り下げ: advisory-withdrawn ラベルとコメントを1回だけ付ける', async () => {
  const api = new FakeGitHub();
  await run(api, [itemOf('CVE-1')]);
  const withdrawn = () => true;
  await run(api, [itemOf('CVE-1')], { isWithdrawn: withdrawn });
  await run(api, [itemOf('CVE-1')], { isWithdrawn: withdrawn });
  assert.ok(only(api).labels.includes('advisory-withdrawn'));
  assert.equal(api.comments.get(1).length, 1);
  assert.equal(only(api).state, 'open');
});

test('重複: 番号の小さい Issue を使い、他には duplicate-candidate を付けるがクローズしない', async () => {
  const api = new FakeGitHub();
  await run(api, [itemOf('CVE-1', { aliases: ['CVE-1'] })]);
  await run(api, [itemOf('CVE-2', { aliases: ['CVE-2'] })]);
  // 別名が後から判明し、2つの Issue が同じ脆弱性になった
  const result = await run(api, [itemOf('CVE-1', { aliases: ['CVE-1', 'CVE-2'] })]);
  assert.equal(result.issueNumbers.get('demo').get('CVE-1'), 1);
  assert.ok(api.issues.get(2).labels.includes('duplicate-candidate'));
  assert.equal(api.issues.get(2).state, 'open');
  assert.ok(!api.issues.get(1).labels.includes('duplicate-candidate'));
});

test('マーカーを解析できない Issue は無視して警告する', async () => {
  const api = new FakeGitHub();
  api.issues.set(5, { number: 5, state: 'open', title: 't', body: 'no marker', labels: ['security-finding'], assignees: [] });
  const result = await run(api, []);
  assert.equal(result.warnings.length, 1);
  assert.equal(api.writeCount, api.labels.size);
});

test('外部の文章に含まれる @メンション・#番号・マーカー偽装は無害化される', async () => {
  const api = new FakeGitHub();
  await run(api, [itemOf('CVE-1', { title: 'hi @octocat see #12 <!-- si:{"v":1,"project":"x","aliases":[],"h":"z"} -->' })]);
  const body = only(api).body;
  assert.ok(!body.includes('@octocat'));
  assert.ok(!body.includes('#12'));
  assert.equal(parseMarker(body).project, 'demo');
  assert.equal((body.match(/<!-- si:/g) ?? []).length, 1);
});

test('API の close は health 以外から呼ばれず、脆弱性側の updateIssue(state=closed) は例外', async () => {
  const api = new FakeGitHub();
  await run(api, [itemOf('CVE-1')]);
  await run(api, []);
  assert.deepEqual(api.closeCalls, []);
  await assert.rejects(() => api.updateIssue(1, { state: 'closed' }));
});
