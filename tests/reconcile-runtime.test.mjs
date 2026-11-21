import test from 'node:test';
import assert from 'node:assert/strict';
import { reconcileIssues } from '../src/publish/issues-reconcile.mjs';
import { parseMarker, buildMarker, withMarker, LABELS } from '../src/publish/issue-body.mjs';
import { runtimeGroups } from '../src/publish/runtime-groups.mjs';
import { renderDigest } from '../src/publish/digest.mjs';
import { buildHealth } from '../src/publish/health.mjs';
import { loadSchedule } from '../src/lib/config.mjs';
import { FakeGitHub } from './helpers/fake-github.mjs';

const NOW = '2026-10-25T00:00:00Z';
const project = { project: 'demo', owners: ['alice'] };
let idCounter = 0;
const generateId = () => `id${++idCounter}`;

const loc = (version, at = NOW) => ({ lockfile: '.security/stack.yml', package: 'php', ecosystem: 'runtime', installed_version: version, last_confirmed_at: at, last_confirmed_provenance: {} });
const rt = (key, overrides = {}) => ({
  advisory_key: key, aliases: [key], title: key, locations: [loc('8.1.21')], fixed_versions: ['8.1.29'], source_urls: ['https://example.com/x'],
  judgement: 'affected', priority: 'P1', evidence: 'ev', kev: false, issue_number: null, first_detected_at: NOW, last_confirmed_at: NOW, last_confirmed_provenance: {}, ...overrides,
});
const npm = (key) => ({ ...rt(key), locations: [{ ...loc('1.0.0'), lockfile: 'package-lock.json', package: 'pkg', ecosystem: 'npm' }] });
const run = (api, items, o = {}) => reconcileIssues({
  api, projects: [project], findingsByProject: new Map([['demo', { project: 'demo', scan_status: o.scanStatus ?? 'complete', items }]]), now: o.now ?? NOW, generateId, isWithdrawnAliases: o.isWithdrawn,
});
const marker = (issue) => parseMarker(issue.body);
const groupIssues = (api) => [...api.issues.values()].filter((i) => marker(i).aliases.some((a) => a.startsWith('RUNTIME-')));
const legacy = async (api, key) => api.createIssue({ title: `[P1][demo] ${key} php`, body: withMarker('旧', buildMarker({ project: 'demo', aliases: [key], hash: 'x' })), labels: ['security-finding', 'P1'], assignees: ['alice'] });
const commentCount = (api) => [...api.comments.values()].flat().length;
const withdrawing = (...keys) => (aliases) => aliases.some((a) => keys.includes(a));

test('1. 同じ版のランタイムの3項目は Issue 1件になり、members の番号は同じ', async () => {
  const api = new FakeGitHub();
  const result = await run(api, [rt('CVE-1'), rt('CVE-2'), rt('CVE-3', { priority: 'P2' })]);
  assert.equal(api.issues.size, 1);
  const issue = api.issues.get(1);
  assert.equal(issue.title, '[P1][demo] php 8.1.21 の脆弱性 3件');
  assert.deepEqual(marker(issue).mk, ['CVE-1', 'CVE-2', 'CVE-3']);
  assert.match(issue.body, /### 含まれる脆弱性/);
  const numbers = result.issueNumbers.get('demo');
  assert.deepEqual(['CVE-1', 'CVE-2', 'CVE-3'].map((k) => numbers.get(k)), [1, 1, 1]);
});

test('2. 2回目は何も変わらない（PATCH もコメントもない）', async () => {
  const api = new FakeGitHub();
  await run(api, [rt('CVE-1'), rt('CVE-2')]);
  api.resetWrites();
  await run(api, [rt('CVE-2'), rt('CVE-1')]);
  assert.equal(api.writeCount, 0);
});

test('3. members が増えると同じ Issue の本文・タイトル・mk だけが更新される', async () => {
  const api = new FakeGitHub();
  await run(api, [rt('CVE-1')]);
  await run(api, [rt('CVE-1'), rt('CVE-2')]);
  assert.equal(api.issues.size, 1);
  assert.match(api.issues.get(1).title, /2件$/);
  assert.deepEqual(marker(api.issues.get(1)).mk, ['CVE-1', 'CVE-2']);
  assert.equal(commentCount(api), 0);
});

test('4. 版が変わると旧まとめに fixed-in-repo が付き、新しい版のまとめができる', async () => {
  const api = new FakeGitHub();
  await run(api, [rt('CVE-1')]);
  await run(api, [rt('CVE-1', { locations: [loc('8.3.36')] })]);
  assert.equal(api.issues.size, 2);
  assert.ok(api.issues.get(1).labels.includes('fixed-in-repo'));
  assert.match(api.issues.get(2).title, /php 8\.3\.36/);
  assert.equal(commentCount(api), 0);
});

test('5. 旧来の CVE ごとの Issue は superseded と sb が付き、fixed-in-repo もコメントも close もない。closed は再オープンしない', async () => {
  const api = new FakeGitHub();
  await legacy(api, 'CVE-1');
  await legacy(api, 'CVE-2');
  api.humanClose(2);
  await run(api, [rt('CVE-1'), rt('CVE-2')]);
  assert.equal(api.issues.size, 3);
  for (const number of [1, 2]) {
    const issue = api.issues.get(number);
    assert.ok(issue.labels.includes('superseded'));
    assert.ok(!issue.labels.includes('fixed-in-repo'));
    assert.equal(marker(issue).sb, 3);
  }
  assert.equal(api.issues.get(1).state, 'open');
  assert.equal(api.issues.get(2).state, 'closed');
  assert.equal(commentCount(api), 0);
  assert.deepEqual(api.closeCalls, []);
  api.resetWrites();
  await run(api, [rt('CVE-1'), rt('CVE-2')]);
  assert.equal(api.writeCount, 0);
});

test('6. まとめ Issue の作成 API が失敗 → 旧 Issue は何も変わらず、未解決の件数に残る。次の実行で移行される', async () => {
  const api = new FakeGitHub();
  await legacy(api, 'CVE-1');
  const before = JSON.stringify(api.issues.get(1));
  api.failNext('createIssue', () => true, 1);
  const failed = await run(api, [rt('CVE-1')]);
  assert.equal(JSON.stringify(api.issues.get(1)), before);
  assert.ok(failed.warnings.some((w) => w.includes('見送り')));
  assert.equal(failed.snapshot.find((s) => s.issue_number === 1).superseded_by, null);
  const health = buildHealth({ previous: null, now: NOW, startedAt: NOW, status: 'success', sourceResults: {}, projectStates: {}, osvMeta: {}, packagistUpdatedSince: null });
  const digest = renderDigest({ projects: [project], findingsByProject: new Map(), snapshot: failed.snapshot, digestInfo: failed.digestInfo, health, schedule: loadSchedule(), now: NOW, centralRepo: 'o/c', kevRecords: [], jpItems: [] });
  assert.match(digest, /\| demo \|.*\| 0 \/ 1 \/ 0 \|/, '旧 Issue は未解決に数えられる');
  await run(api, [rt('CVE-1')]);
  assert.equal(marker(api.issues.get(1)).sb, 2);
  assert.ok(api.issues.get(1).labels.includes('superseded'));
});

test('7. 移行の後に members が消えても移行済み Issue は superseded のまま。まとめ Issue だけ fixed-in-repo になる', async () => {
  const api = new FakeGitHub();
  await legacy(api, 'CVE-1');
  await run(api, [rt('CVE-1')]);
  const result = await run(api, []);
  assert.ok(!api.issues.get(1).labels.includes('fixed-in-repo'));
  assert.ok(api.issues.get(1).labels.includes('superseded'));
  assert.ok(api.issues.get(2).labels.includes('fixed-in-repo'));
  assert.deepEqual(result.digestInfo.fixedInRepo.map((f) => f.issue_number), [2]);
  assert.deepEqual(result.digestInfo.superseded, [{ issue_number: 1, project: 'demo', superseded_by: 2 }]);
  api.resetWrites();
  await run(api, []);
  assert.equal(api.writeCount, 0);
});

test('8. superseded ラベルを人が外すと付け直され、fixed-in-repo を人が付けると外される', async () => {
  const api = new FakeGitHub();
  await legacy(api, 'CVE-1');
  await run(api, [rt('CVE-1')]);
  api.issues.get(1).labels = api.issues.get(1).labels.filter((l) => l !== 'superseded');
  api.humanLabel(1, 'fixed-in-repo', NOW);
  await run(api, [rt('CVE-1')]);
  assert.ok(api.issues.get(1).labels.includes('superseded'));
  assert.ok(!api.issues.get(1).labels.includes('fixed-in-repo'));
});

test('9. KEV の集約: P3 の KEV と P1 の非 KEV のまとめは kev=false。受容は解除されず、KEV が P0 になると解除される', async () => {
  const api = new FakeGitHub();
  const items = (kevItem) => [rt('CVE-1', { priority: 'P1' }), rt('CVE-KEV', kevItem)];
  const lowKev = { priority: 'P3', judgement: 'needs_review', kev: true };
  await run(api, items(lowKev));
  assert.deepEqual(groupIssues(api).map((i) => i.labels.includes('P1')), [true]);
  assert.match(api.issues.get(1).body, /KEV 掲載: 1件（うち P0 0件）/);
  api.humanLabel(1, 'risk-accepted', '2026-10-01T00:00:00Z');
  api.humanClose(1);
  api.resetWrites();
  await run(api, items(lowKev), { now: '2026-11-01T00:00:00Z' });
  assert.equal(api.writeCount, 0);
  assert.equal(api.issues.get(1).state, 'closed');
  await run(api, items({ priority: 'P0', kev: true }), { now: '2026-11-01T00:00:00Z' });
  assert.equal(api.issues.get(1).state, 'open');
  assert.match(api.comments.get(1).at(-1).body, /KEV/);
  assert.match(api.comments.get(1).at(-1).body, /優先度/);
});

test('10. members の取り下げ: 通知は1回だけで advisory-withdrawn は付かない。他の理由で消えても通知しない。コメント失敗は次回に1回送る', async () => {
  const api = new FakeGitHub();
  await run(api, [rt('CVE-A'), rt('CVE-B')]);
  await run(api, [rt('CVE-A')], { isWithdrawn: withdrawing('CVE-B') });
  await run(api, [rt('CVE-A')], { isWithdrawn: withdrawing('CVE-B') });
  assert.equal(api.comments.get(1).length, 1);
  assert.match(api.comments.get(1)[0].body, /CVE-B/);
  assert.ok(!api.issues.get(1).labels.includes('advisory-withdrawn'));
  assert.deepEqual(marker(api.issues.get(1)).mk, ['CVE-A']);

  const other = new FakeGitHub();
  await run(other, [rt('CVE-A'), rt('CVE-B')]);
  await run(other, [rt('CVE-A')]);
  assert.equal(commentCount(other), 0, '取り下げ以外の理由では通知しない');

  const flaky = new FakeGitHub();
  await run(flaky, [rt('CVE-A'), rt('CVE-B')]);
  flaky.failNext('createComment', () => true, 1);
  await run(flaky, [rt('CVE-A')], { isWithdrawn: withdrawing('CVE-B') });
  assert.equal(commentCount(flaky), 0);
  await run(flaky, [rt('CVE-A')], { isWithdrawn: withdrawing('CVE-B') });
  await run(flaky, [rt('CVE-A')], { isWithdrawn: withdrawing('CVE-B') });
  assert.equal(flaky.comments.get(1).length, 1);
});

test('11. sb / mk がない既存 Issue と、型が不正な sb / mk を持つ Issue は例外にならず、マーカー全体は有効', async () => {
  const bad = { v: 1, project: 'demo', aliases: ['CVE-1'], h: 'x', sb: 'oops', mk: 'oops' };
  const body = `旧\n\n<!-- si:${JSON.stringify(bad)} -->`;
  const parsed = parseMarker(body);
  assert.deepEqual(parsed.ignored, ['sb', 'mk']);
  assert.equal(parsed.sb, undefined);
  assert.equal(parsed.project, 'demo');
  assert.deepEqual(parseMarker(`旧\n\n<!-- si:${JSON.stringify({ ...bad, sb: undefined, mk: undefined })} -->`).ignored, []);
  const api = new FakeGitHub();
  api.issues.set(1, { number: 1, state: 'open', title: 't', body, labels: ['security-finding', 'P1'], assignees: [] });
  const result = await run(api, [npm('CVE-1')]);
  assert.equal(result.errors.length, 0);
  assert.equal(result.warnings.filter((w) => w.includes('型が不正')).length, 2);
  assert.equal(api.issues.size, 1);
});

test('12. ランタイム以外は CVE ごとのまま', async () => {
  const api = new FakeGitHub();
  await run(api, [npm('CVE-1'), npm('CVE-2')]);
  assert.equal(api.issues.size, 2);
});

test('13. members がすべて P3 なら起票しない', async () => {
  const api = new FakeGitHub();
  await run(api, [rt('CVE-1', { priority: 'P3', judgement: 'needs_review' }), rt('CVE-2', { priority: 'P3', judgement: 'needs_review' })]);
  assert.equal(api.issues.size, 0);
});

test('14. 版の更新＋partial: 移行済みの旧 Issue は再オープンも重複もされず、旧まとめは complete の回に解消される', async () => {
  const api = new FakeGitHub();
  await legacy(api, 'CVE-1');
  await run(api, [rt('CVE-1')]);
  api.humanClose(1);
  const both = rt('CVE-1', { locations: [loc('8.1.21'), loc('8.3.36', '2026-10-26T00:00:00Z')] });
  const partial = await run(api, [both], { scanStatus: 'partial', now: '2026-10-26T00:00:00Z' });
  assert.equal(api.issues.get(1).state, 'closed');
  assert.ok(!api.issues.get(1).labels.includes('duplicate-candidate'));
  assert.equal(groupIssues(api).length, 2);
  assert.ok([...api.issues.values()].every((i) => !marker(i).aliases.includes('CVE-1') || i.number === 1), 'CVE ごとの Issue は新しく作られない');
  assert.ok(!api.issues.get(2).labels.includes('fixed-in-repo'));
  assert.match(api.issues.get(3).title, /php 8\.3\.36/);
  assert.equal(partial.issueNumbers.get('demo').get('CVE-1'), 3, '新しい location のまとめの番号');
  await run(api, [rt('CVE-1', { locations: [loc('8.3.36', '2026-10-26T00:00:00Z')] })], { now: '2026-10-26T01:00:00Z' });
  assert.ok(api.issues.get(2).labels.includes('fixed-in-repo'));
  assert.ok(!api.issues.get(3).labels.includes('fixed-in-repo'));
  assert.equal(api.issues.get(1).state, 'closed');
});

test('15. 最後の member の取り下げ: advisory-withdrawn と通知は1回だけ、fixed-in-repo は付かず mk は残る。再検出で mk が更新される', async () => {
  const api = new FakeGitHub();
  await run(api, [rt('CVE-A')]);
  const withdrawn = withdrawing('CVE-A');
  await run(api, [], { isWithdrawn: withdrawn });
  assert.ok(api.issues.get(1).labels.includes('advisory-withdrawn'));
  assert.ok(!api.issues.get(1).labels.includes('fixed-in-repo'));
  assert.deepEqual(marker(api.issues.get(1)).mk, ['CVE-A']);
  assert.equal(api.comments.get(1).length, 1);
  api.resetWrites();
  await run(api, [], { isWithdrawn: withdrawn });
  await run(api, [], { isWithdrawn: withdrawn });
  assert.equal(api.writeCount, 0);
  await run(api, [rt('CVE-A'), rt('CVE-C')]);
  assert.deepEqual(marker(api.issues.get(1)).mk, ['CVE-A', 'CVE-C']);
});

test('16. 一部の取り下げと解消が同じ回: member_withdrawn が1回送られ fixed-in-repo が付く', async () => {
  const api = new FakeGitHub();
  await run(api, [rt('CVE-A'), rt('CVE-B')]);
  await run(api, [], { isWithdrawn: withdrawing('CVE-A') });
  assert.equal(api.comments.get(1).length, 1);
  assert.match(api.comments.get(1)[0].body, /CVE-A/);
  assert.ok(api.issues.get(1).labels.includes('fixed-in-repo'));
  assert.ok(!api.issues.get(1).labels.includes('advisory-withdrawn'));
  api.resetWrites();
  await run(api, [], { isWithdrawn: withdrawing('CVE-A') });
  assert.equal(api.writeCount, 0);
});

test('17. runtimeGroups: location が2つの item は両方のまとめの member。順序に依存せず、kev と kev_members が分かれる', () => {
  const two = rt('CVE-1', { priority: 'P0', kev: true, locations: [loc('8.1.21'), loc('8.3.36')] });
  const lowKev = rt('CVE-2', { priority: 'P3', judgement: 'needs_review', kev: true });
  const plain = rt('CVE-3', { priority: 'P1' });
  const forward = runtimeGroups([two, lowKev, plain, npm('CVE-9')]);
  const backward = runtimeGroups([npm('CVE-9'), plain, lowKev, two]);
  assert.deepEqual(forward.issueItems.map((i) => i.advisory_key), ['CVE-9', 'RUNTIME-php-8.1.21', 'RUNTIME-php-8.3.36']);
  assert.deepEqual(forward.memberKeys.get('RUNTIME-php-8.3.36'), ['CVE-1']);
  assert.deepEqual(forward.memberKeys.get('RUNTIME-php-8.1.21'), ['CVE-1', 'CVE-3', 'CVE-2']);
  assert.deepEqual(forward, backward);
  const [, old] = forward.issueItems;
  assert.equal(old.kev, true);
  assert.deepEqual(old.kev_members, ['CVE-1', 'CVE-2']);
  const onlyLow = runtimeGroups([lowKev, plain]).issueItems[0];
  assert.equal(onlyLow.kev, false);
  assert.deepEqual(onlyLow.kev_members, ['CVE-2']);
  assert.equal(runtimeGroups([rt('RUNTIME-UNKNOWN-php')]).issueItems[0].members, undefined, 'UNKNOWN はまとめない');
});

test('まとめの本文: 表の外部の文字列は無害化される（メンション・番号・HTML・表の区切り）', async () => {
  const api = new FakeGitHub();
  await run(api, [rt('CVE-1', { fixed_versions: ['@evil|<b>#12'], source_urls: ['javascript:alert(1)'] })]);
  const table = api.issues.get(1).body.split('### 含まれる脆弱性')[1].split('### 概要')[0];
  assert.ok(!table.includes('@evil') && !table.includes('<b>') && !table.includes('#12'));
  assert.match(table, /\\\|/, 'パイプはエスケープされる');
  assert.equal(LABELS.superseded, 'superseded');
});
