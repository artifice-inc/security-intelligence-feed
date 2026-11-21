import test from 'node:test';
import assert from 'node:assert/strict';
import { reconcileIssues } from '../src/publish/issues-reconcile.mjs';
import { parseMarker, renderBody, LABELS } from '../src/publish/issue-body.mjs';
import { buildCentralIssues } from '../src/local/check-summary.mjs';
import { mergeFindings } from '../src/match/findings-merge.mjs';
import { assembleItems } from '../src/match/assemble.mjs';
import { movedMembers } from '../src/publish/runtime-migration.mjs';
import { assertValid } from '../src/lib/schema.mjs';
import { FakeGitHub } from './helpers/fake-github.mjs';
import { NOW, PROVENANCE } from './helpers/match-fixtures.mjs';

const project = { project: 'demo', owners: ['alice'] };
let counter = 0;
const generateId = () => `py${++counter}`;
const LATER = '2026-10-26T00:00:00Z';

const loc = (overrides = {}) => ({ lockfile: '.python-version', package: 'python', ecosystem: 'runtime', installed_version: '3.12.7', last_confirmed_at: NOW, last_confirmed_provenance: {}, ...overrides });
const item = (key, overrides = {}) => ({
  advisory_key: key, aliases: [key], title: key, locations: [loc()], fixed_versions: ['3.12.14'], source_urls: ['https://example.com/x'],
  judgement: 'affected', priority: 'P2', evidence: 'ev', kev: false, issue_number: null, first_detected_at: NOW, last_confirmed_at: NOW, last_confirmed_provenance: {}, ...overrides,
});
// CPython と PyPI の lockfile の両方で検出された item（混在 item）
const mixed = (key, { runtimeJudgement = 'affected', pypiJudgement = 'affected' } = {}) => item(key, {
  aliases: [key], fixed_versions: ['2.0.0', '3.12.14'],
  locations: [loc({ fixed_versions: ['3.12.14'], judgement: runtimeJudgement }), loc({ lockfile: 'poetry.lock', package: 'pkg', ecosystem: 'PyPI', installed_version: '1.0.0', fixed_versions: ['2.0.0'], judgement: pypiJudgement })],
});
const run = (api, items, o = {}) => reconcileIssues({
  api, projects: [project], findingsByProject: new Map([['demo', { project: 'demo', scan_status: o.scanStatus ?? 'complete', scanned_at: o.now ?? NOW, items }]]), now: o.now ?? NOW, generateId,
});
const marker = (issue) => parseMarker(issue.body);
const groupOf = (api) => [...api.issues.values()].find((i) => marker(i).mk);

test('旧まとめの唯一の member が混在 item に移った回（complete）: CVE 単位の Issue ができ、旧まとめは superseded（sb が新しい番号）で fixed-in-repo は付かない', async () => {
  const api = new FakeGitHub();
  await run(api, [item('CVE-X')]);
  assert.deepEqual(marker(groupOf(api)).mk, ['CVE-X']);
  const groupNumber = groupOf(api).number;
  await run(api, [mixed('CVE-X')]);
  const created = [...api.issues.values()].find((i) => i.number !== groupNumber);
  assert.ok(created, 'CVE 単位の Issue が作られる');
  const group = api.issues.get(groupNumber);
  assert.ok(!group.labels.includes(LABELS.fixed), 'fixed-in-repo を付けない');
  assert.ok(group.labels.includes(LABELS.superseded));
  assert.equal(marker(group).sb, created.number);
  assert.deepEqual(marker(group).mk, ['CVE-X'], 'mk は保つ');
  // 次の回も安定（書き込みなし）
  api.resetWrites();
  await run(api, [mixed('CVE-X')]);
  assert.equal(api.writeCount, 0);
});

test('新しい Issue の作成に失敗した回は、旧まとめは変わらない。次の回に作成されたら移行される', async () => {
  const api = new FakeGitHub();
  await run(api, [item('CVE-X')]);
  const groupNumber = groupOf(api).number;
  const before = JSON.stringify(api.issues.get(groupNumber));
  api.failNext('createIssue');
  const failed = await run(api, [mixed('CVE-X')]);
  assert.ok(failed.errors.length > 0);
  assert.equal(JSON.stringify(api.issues.get(groupNumber)), before, 'fixed-in-repo も superseded も付かない');
  await run(api, [mixed('CVE-X')]);
  const group = api.issues.get(groupNumber);
  assert.ok(group.labels.includes(LABELS.superseded) && !group.labels.includes(LABELS.fixed));
  assert.equal(marker(group).sb, 2);
});

test('2つの member のうち1つが混在 item に移り、もう1つが解消した回: 移行として扱う', async () => {
  const api = new FakeGitHub();
  await run(api, [item('CVE-X'), item('CVE-Y')]);
  const groupNumber = groupOf(api).number;
  await run(api, [mixed('CVE-X')]);
  const group = api.issues.get(groupNumber);
  assert.ok(group.labels.includes(LABELS.superseded) && !group.labels.includes(LABELS.fixed));
  assert.equal(marker(group).sb, 2);
});

test('移った member がない（本当に解消した）回は、今までどおり fixed-in-repo が付く。partial の回は付かない', async () => {
  const api = new FakeGitHub();
  await run(api, [item('CVE-X')]);
  const groupNumber = groupOf(api).number;
  await run(api, [], { scanStatus: 'partial' });
  assert.ok(!api.issues.get(groupNumber).labels.includes(LABELS.fixed));
  await run(api, []);
  assert.ok(api.issues.get(groupNumber).labels.includes(LABELS.fixed));
  assert.equal(marker(api.issues.get(groupNumber)).sb, undefined);
});

test('movedMembers: まとめの item は対象外。番号のない item があれば number は null（何もしない）', () => {
  const issue = { marker: { mk: ['CVE-X', 'CVE-Y'] } };
  const group = { advisory_key: 'RUNTIME-python-3.12.7', aliases: ['RUNTIME-python-3.12.7'], members: [{}] };
  assert.deepEqual(movedMembers(issue, [group], new Map()), { matched: false, number: null });
  const a = item('CVE-X');
  const b = item('CVE-Y');
  assert.deepEqual(movedMembers(issue, [a, b], new Map([['CVE-X', 7], ['CVE-Y', 5]])), { matched: true, number: 5 });
  assert.deepEqual(movedMembers(issue, [a, b], new Map([['CVE-X', 7]])), { matched: true, number: null });
  assert.deepEqual(movedMembers({ marker: {} }, [a], new Map([['CVE-X', 7]])), { matched: false, number: null });
});

test('issues.json の各 Issue に member_keys（まとめは mk、それ以外は空配列）が入り、スキーマを通る', async () => {
  const api = new FakeGitHub();
  const result = await run(api, [item('CVE-X'), item('CVE-Z', { locations: [loc({ lockfile: 'package-lock.json', package: 'p', ecosystem: 'npm' })] })]);
  assert.deepEqual(Object.fromEntries(result.snapshot.map((s) => [s.aliases[0], s.member_keys])), { 'RUNTIME-python-3.12.7': ['CVE-X'], 'CVE-Z': [] });
  assertValid('issues', result.snapshot);
});

test('ローカル: 中央の移行前の issues.json（旧まとめが open、member_keys に CVE-X）で、手元に CVE-X の混在 item がある → resolved_locally に入らない', () => {
  const issuesFile = [
    { issue_number: 1, project: 'demo', aliases: ['RUNTIME-python-3.12.7'], state: 'open', labels: ['P2'], member_keys: ['CVE-X'] },
    { issue_number: 2, project: 'demo', aliases: ['RUNTIME-python-3.12.8'], state: 'open', labels: ['P2'], member_keys: ['CVE-GONE'] },
    { issue_number: 3, project: 'demo', aliases: ['CVE-OLD'], state: 'open', labels: ['P2'], member_keys: [] },
  ];
  const mixedItem = mixed('CVE-X');
  const common = { issuesFile, projectName: 'demo', localScan: { complete: true, reasons: [] } };
  // まとめに入らない混在 item の aliases は aliasSets（まとめ後）に出てこないが、itemAliasSets（items そのもの）で見つかる
  const result = buildCentralIssues({ ...common, aliasSets: [], itemAliasSets: [mixedItem.aliases] });
  assert.deepEqual(result.resolved_locally.map((c) => c.issue_number), [2, 3]);
  // itemAliasSets を渡さない既存の呼び方は、今までどおり（member_keys があっても aliasSets で見る）
  assert.deepEqual(buildCentralIssues({ ...common, aliasSets: [['CVE-X']] }).resolved_locally.map((c) => c.issue_number), [2, 3]);
  assert.equal(buildCentralIssues({ ...common, aliasSets: [], localScan: { complete: false, reasons: ['x'] }, itemAliasSets: [] }).resolved_locally, null);
  // member_keys のない（古い）issues.json は今までどおり
  const legacy = [{ issue_number: 1, project: 'demo', aliases: ['RUNTIME-php-8.1.21'], state: 'open', labels: ['P1'] }];
  assert.deepEqual(buildCentralIssues({ issuesFile: legacy, projectName: 'demo', localScan: { complete: true, reasons: [] }, aliasSets: [] }).resolved_locally.map((c) => c.issue_number), [1]);
});

// ---- 混在 item の組み立て・本文・partial ------------------------------------------------------

const det = (overrides) => ({ lockfile: '.python-version', package: 'python', ecosystem: 'runtime', installed_version: '3.12.7', aliases: ['CVE-X'], title: 't', judgement: 'affected', fixed_versions: ['3.12.14'], evidence: 'e', ...overrides });
const pypiDet = (overrides) => det({ lockfile: 'poetry.lock', package: 'pkg', ecosystem: 'PyPI', installed_version: '1.0.0', fixed_versions: ['2.0.0'], osv_id: 'GHSA-x', aliases: ['GHSA-x', 'CVE-X'], ...overrides });
const assemble = (detections) => assembleItems({ detections, index: new Map(), exposure: 'internal', now: NOW, provenance: PROVENANCE });

test('assemble: 混在 item の各 location に fixed_versions と judgement が入る。item の judgement は今までどおり（どれかが affected なら affected）', () => {
  const [it] = assemble([det({ judgement: 'needs_review', fixed_versions: [] }), pypiDet()]);
  assert.equal(it.locations.length, 2);
  const byLock = Object.fromEntries(it.locations.map((l) => [l.lockfile, [l.fixed_versions, l.judgement]]));
  assert.deepEqual(byLock, { '.python-version': [[], 'needs_review'], 'poetry.lock': [['2.0.0'], 'affected'] });
  assert.equal(it.judgement, 'affected');
  assert.deepEqual(it.fixed_versions, ['2.0.0'], 'item の和は今のまま');
  assertValid('findings', { project: 'demo', monitor_ref: 'm', scanned_at: NOW, inventory_as_of: null, inventory_status: 'fresh', scan_status: 'complete', scan_errors: [], provenance: PROVENANCE, items: [it] });
});

test('assemble: 混在でない item（CPython だけ・PyPI だけ・npm だけ）には location の fixed_versions・judgement を足さない', () => {
  for (const detections of [[det()], [pypiDet({ aliases: ['GHSA-y'] })], [pypiDet({ aliases: ['GHSA-z'], ecosystem: 'npm', lockfile: 'package-lock.json' })]]) {
    const [it] = assemble(detections);
    for (const l of it.locations) assert.ok(!('fixed_versions' in l) && !('judgement' in l));
  }
  const two = assemble([det({ installed_version: '3.12.7' }), det({ installed_version: '3.13.0', lockfile: 'Dockerfile' })]);
  assert.ok(two[0].locations.every((l) => !('judgement' in l)), 'runtime だけの複数の箇所も混在ではない');
});

test('Issue 本文: 混在 item は箇所ごとの判定と修正版を出す。CPython 側が要確認なら「要確認」。混在でない item の本文は変わらない', () => {
  const body = renderBody({ project: 'demo', item: mixed('CVE-X', { runtimeJudgement: 'needs_review' }), owners: ['alice'] });
  assert.match(body, /\| 判定 \| 修正版 \|/);
  assert.match(body, /\| \.python-version \| python \| 3\.12\.7 \| 要確認 \| 3\.12\.14 \|/);
  assert.match(body, /\| poetry\.lock \| pkg \| 1\.0\.0 \| 影響あり \| 2\.0\.0 \|/);
  assert.match(body, /- \.{0}python（python）: 要確認、修正版 `3\.12\.14`/);
  assert.match(body, /- poetry\.lock（pkg）: 影響あり、修正版 `2\.0\.0`/);
  assert.ok(!body.includes('両方に影響'));
  const plain = renderBody({ project: 'demo', item: item('CVE-N'), owners: ['alice'] });
  assert.ok(plain.includes('| lockfile / 検出元 | パッケージ | 導入されている版 |\n|---|---|---|'));
  assert.ok(!plain.includes('| 判定 |'));
  assert.match(plain, /### 修正版\n\n- `3\.12\.14`/);
});

test('Issue 本文: この回に再確認できなかった箇所には「前回の値（この回は未確認）」を添える。再確認できた回は添えない', () => {
  const stale = mixed('CVE-X');
  stale.locations[1].last_confirmed_at = '2026-10-20T00:00:00Z';
  stale.locations[0].last_confirmed_at = '2026-10-25T00:00:00Z';
  const body = renderBody({ project: 'demo', item: stale, owners: ['alice'], scannedAt: '2026-10-25T00:00:00Z' });
  assert.match(body, /\| poetry\.lock \| pkg \| 1\.0\.0 \| 影響あり（前回の値。この回は未確認） \|/);
  assert.match(body, /\| \.python-version \| python \| 3\.12\.7 \| 影響あり \|/);
  assert.ok(!renderBody({ project: 'demo', item: mixed('CVE-X'), owners: ['alice'], scannedAt: NOW }).includes('前回の値'));
});

// partial の回: 前回は PyPI 側が affected・CPython 側が needs_review。今回は PyPI の DB を取れず CPython 側だけ照合できた
const status = (scanStatus, at) => ({ project: 'demo', monitor_ref: 'm', inventory_status: 'fresh', scan_status: scanStatus, scan_errors: [], provenance: PROVENANCE, scanned_at: at, inventory_as_of: at });
const itemAt = (detections, at) => assembleItems({ detections, index: new Map(), exposure: 'internet', now: at, provenance: PROVENANCE });

test('partial の統合: 前回 affected の箇所を保持したまま item 全体が needs_review・P3 に下がらない。次の complete の回に今回の結果に戻る', () => {
  const previous = mergeFindings({ previous: null, current: itemAt([det({ judgement: 'needs_review', fixed_versions: [] }), pypiDet()], NOW), status: status('complete', NOW) });
  assert.equal(previous.items[0].priority, 'P2');
  const current = itemAt([det({ judgement: 'needs_review', fixed_versions: [] })], LATER);
  assert.equal(current[0].priority, 'P3');
  const partial = mergeFindings({ previous, current, status: status('partial', LATER) });
  const [merged] = partial.items;
  assert.deepEqual([merged.judgement, merged.priority], ['affected', 'P2']);
  assert.deepEqual(merged.fixed_versions, ['2.0.0']);
  const byLock = Object.fromEntries(merged.locations.map((l) => [l.lockfile, [l.last_confirmed_at, l.judgement]]));
  assert.deepEqual(byLock, { '.python-version': [LATER, 'needs_review'], 'poetry.lock': [NOW, 'affected'] }, 'PyPI の箇所は前回の時刻・値のまま');
  const next = mergeFindings({ previous: partial, current, status: status('complete', '2026-10-27T00:00:00Z') });
  assert.deepEqual([next.items[0].judgement, next.items[0].priority, next.items[0].locations.length], ['needs_review', 'P3', 1]);
});

test('partial の統合: 条件を絞る（前回も今回も affected、保持した箇所がない、前回が needs_review のときは今回の値のまま）', () => {
  const before = mergeFindings({ previous: null, current: itemAt([pypiDet(), det()], NOW), status: status('complete', NOW) });
  const both = mergeFindings({ previous: before, current: itemAt([det({ fixed_versions: ['3.12.15'] })], LATER), status: status('partial', LATER) });
  assert.equal(both.items[0].judgement, 'affected');
  assert.deepEqual(both.items[0].fixed_versions, ['3.12.15'], '今までどおり（今回の値で置き換え。和にならない）');
  const reviewBefore = mergeFindings({ previous: null, current: itemAt([det({ judgement: 'needs_review' })], NOW), status: status('complete', NOW) });
  const same = mergeFindings({ previous: reviewBefore, current: itemAt([det({ judgement: 'needs_review' })], LATER), status: status('partial', LATER) });
  assert.deepEqual([same.items[0].judgement, same.items[0].priority], ['needs_review', 'P3']);
  const all = mergeFindings({ previous: before, current: itemAt([pypiDet(), det({ judgement: 'needs_review' })], LATER), status: status('partial', LATER) });
  assert.equal(all.items[0].judgement, 'affected', '全箇所を再検出し、今回 item が affected のときは今回の値');
  const refetched = mergeFindings({ previous: itemsWithPrevAffected(), current: itemAt([det({ judgement: 'needs_review' })], LATER), status: status('partial', LATER) });
  assert.deepEqual([refetched.items[0].judgement, refetched.items[0].priority], ['needs_review', 'P3'], '保持した箇所がなければ今回の値');
});
function itemsWithPrevAffected() {
  return mergeFindings({ previous: null, current: itemAt([det()], NOW), status: status('complete', NOW) });
}
