import test from 'node:test';
import assert from 'node:assert/strict';
import { reconcileIssues } from '../src/publish/issues-reconcile.mjs';
import { parseMarker } from '../src/publish/issue-body.mjs';
import { projectSections } from '../src/publish/digest-project.mjs';
import { loadThresholds } from '../src/lib/config.mjs';
import { FakeGitHub } from './helpers/fake-github.mjs';
import { makeHarness, T0 } from './helpers/central-harness.mjs';

const NOW = '2026-10-25T00:00:00Z';
const project = { project: 'demo', owners: ['alice'] };
let idCounter = 0;
const generateId = () => `id${++idCounter}`;

const kernelLoc = (pkg = 'kernel6.18', version = 'al2023') => ({ lockfile: '.security/stack.yml', package: pkg, ecosystem: 'os', installed_version: version, last_confirmed_at: NOW, last_confirmed_provenance: {} });
const base = (key, locations, overrides) => ({
  advisory_key: key, aliases: [key], title: key, locations, fixed_versions: [], source_urls: ['https://explore.alas.aws.amazon.com/x.html'],
  judgement: 'affected', priority: 'P1', evidence: 'ev', kev: false, issue_number: null, first_detected_at: NOW, last_confirmed_at: NOW, last_confirmed_provenance: {}, ...overrides,
});
const kn = (key, overrides = {}) => base(key, [kernelLoc()], overrides);
const rt = (key, overrides = {}) => base(key, [{ ...kernelLoc('php', '8.1.21'), ecosystem: 'runtime' }], { fixed_versions: ['8.1.29'], ...overrides });
const run = (api, items, o = {}) => reconcileIssues({
  api, projects: [project], findingsByProject: new Map([['demo', { project: 'demo', scan_status: o.scanStatus ?? 'complete', items }]]), now: o.now ?? NOW, generateId,
});
const marker = (issue) => parseMarker(issue.body);
const comments = (api, number = 1) => (api.comments.get(number) ?? []).map((c) => c.body);

test('KERNEL のまとめが1件だけ作られ、タイトル・本文が指示書どおり（fixed-in-repo の説明を出さない）', async () => {
  const api = new FakeGitHub();
  const result = await run(api, [kn('CVE-1'), kn('CVE-2', { fixed_versions: ['ALAS2023-2026-3251'] })]);
  assert.equal(api.issues.size, 1);
  const issue = api.issues.get(1);
  assert.equal(issue.title, '[P1][demo] Amazon Linux 2023 のカーネル kernel6.18 の脆弱性 2件');
  assert.deepEqual(marker(issue).aliases, ['KERNEL-al2023-kernel6.18']);
  assert.deepEqual(marker(issue).mk, ['CVE-1', 'CVE-2']);
  assert.match(issue.body, /\| CVE-1 \| P1 \| 影響あり \| 配布元で未修正 \|/);
  assert.match(issue.body, /\| CVE-2 \| P1 \| 影響あり \| ALAS2023-2026-3251 \|/);
  assert.match(issue.body, /この Issue に fixed-in-repo は付きません/);
  assert.match(issue.body, /閉じても再オープンされます/);
  assert.ok(!issue.body.includes('版を上げると'));
  assert.ok(!issue.body.includes('解消すると `fixed-in-repo`'));
  assert.deepEqual(['CVE-1', 'CVE-2'].map((k) => result.issueNumbers.get('demo').get(k)), [1, 1]);
  assert.equal(comments(api).length, 0, '初回の作成では通知しない');
});

test('AL2 の repo 付き: aliases の @ は _ になる', async () => {
  const api = new FakeGitHub();
  await run(api, [base('CVE-1', [kernelLoc('kernel@kernel-5.10', 'al2')])]);
  assert.deepEqual(marker(api.issues.get(1)).aliases, ['KERNEL-al2-kernel_kernel-5.10']);
  // タイトルの @ はメンション防止で零幅スペースが入る
  assert.match(api.issues.get(1).title, /Amazon Linux 2 のカーネル kernel@\u200Bkernel-5\.10 の脆弱性 1件/);
});

test('member_added: P0/P1 が増えた回に1回だけ。再実行・P2/P3 の追加・RUNTIME のまとめでは出ない', async () => {
  const api = new FakeGitHub();
  await run(api, [kn('CVE-1')]);
  await run(api, [kn('CVE-1'), kn('CVE-2')]);
  assert.equal(comments(api).length, 1);
  assert.match(comments(api)[0], /まとめに新しい重大な脆弱性が加わりました：`CVE-2`（P1）/);
  assert.ok(!comments(api)[0].includes('@'), 'メンションなし');
  await run(api, [kn('CVE-1'), kn('CVE-2')]);
  assert.equal(comments(api).length, 1, '同じ状態で再送しない');
  await run(api, [kn('CVE-1'), kn('CVE-2'), kn('CVE-3', { priority: 'P2' }), kn('CVE-4', { priority: 'P3', judgement: 'needs_review' })]);
  assert.equal(comments(api).length, 1, 'P2・P3 では出ない');
  await run(api, [kn('CVE-1'), kn('CVE-2'), kn('CVE-3', { priority: 'P2' }), kn('CVE-4', { priority: 'P3', judgement: 'needs_review' }), kn('CVE-5', { priority: 'P0', kev: true })]);
  assert.equal(comments(api).length, 2);
  assert.match(comments(api)[1], /`CVE-5`（P0）/);

  const runtime = new FakeGitHub();
  await run(runtime, [rt('CVE-1')]);
  await run(runtime, [rt('CVE-1'), rt('CVE-2')]);
  assert.equal(comments(runtime).length, 0, 'RUNTIME のまとめでは通知しない');
});

test('全 members が消えた回（scan complete）も、その次の回も、さらに次の回も fixed-in-repo を付けない。RUNTIME は今までどおり付く', async () => {
  const api = new FakeGitHub();
  await run(api, [kn('CVE-1')]);
  for (let i = 0; i < 3; i += 1) {
    await run(api, []);
    assert.ok(!api.issues.get(1).labels.includes('fixed-in-repo'), `${i + 1}回目`);
    assert.equal(api.issues.get(1).state, 'open');
  }
  assert.deepEqual(marker(api.issues.get(1)).mk, []);
  // members が戻れば、同じ Issue が使われる
  await run(api, [kn('CVE-9')]);
  assert.equal(api.issues.size, 1);

  const runtime = new FakeGitHub();
  await run(runtime, [rt('CVE-1')]);
  await run(runtime, []);
  assert.ok(runtime.issues.get(1).labels.includes('fixed-in-repo'));
});

test('人がクローズしたあと未修正が残っていれば、誤クローズとして再オープンされる', async () => {
  const api = new FakeGitHub();
  await run(api, [kn('CVE-1')]);
  api.humanClose(1);
  await run(api, [kn('CVE-1')]);
  assert.equal(api.issues.get(1).state, 'open');
  assert.match(comments(api).at(-1), /誤クローズ/);
});

test('risk-accepted でクローズ → kev_hint 由来の KEV（P0）で再オープンする', async () => {
  const api = new FakeGitHub();
  const low = kn('CVE-1', { kev: false });
  await run(api, [low]);
  api.humanLabel(1, 'risk-accepted', '2026-10-24T00:00:00Z');
  api.humanClose(1);
  await run(api, [low], { now: '2026-10-26T00:00:00Z' });
  assert.equal(api.issues.get(1).state, 'closed');
  await run(api, [kn('CVE-1', { priority: 'P0', kev: true })], { now: '2026-10-26T00:00:00Z' });
  assert.equal(api.issues.get(1).state, 'open');
  assert.match(comments(api).at(-1), /KEV/);
});

test('digest: まとめの1行が「対応が必要」に出て、.security/stack.yml は lockfile の行に出ない', async () => {
  const api = new FakeGitHub();
  const items = [kn('CVE-1'), kn('CVE-2', { priority: 'P3', judgement: 'needs_review' })];
  const result = await run(api, items);
  const text = projectSections({
    projects: [project], findingsByProject: new Map([['demo', { items }]]), snapshot: result.snapshot, digestInfo: result.digestInfo,
    centralRepo: 'org/central', now: NOW, thresholds: loadThresholds(),
  }).join('\n');
  assert.ok(!text.includes('.security/stack.yml'));
  assert.match(text, /#### 対応が必要（P0〜P2）\n\n- \*\*P1\*\* Amazon Linux 2023 のカーネル kernel6\.18 の脆弱性 2件/);
});

test('中央の実行: 申告した案件ごとにまとめ Issue が1件できる（Fixed は P3 の member として表に載る）', async () => {
  const stack = 'os: linux\nkernel:\n  distro: amazonlinux\n  release: "2023"\n  package: kernel6.18\n';
  const raw = (id, status) => ({ cve_id: id, severity: 'Critical', public_date: '2026-10-01', modified_date: '2026-10-20', scores: [], affected_packages: [{ name: 'kernel6.18', platform: 'amzn2023', advisories: [], status, opt_in_repo: null }] });
  const h = makeHarness({ projectFiles: { 'package-lock.json': '{}', '.nvmrc': '22.11.0', '.security/stack.yml': stack } });
  h.state.collectors.alas = async () => ({ ok: true, records: [raw('CVE-2026-0001', 'PendingFix'), raw('CVE-2026-0002', 'PendingFix'), { ...raw('CVE-2026-0003', 'Fixed'), affected_packages: [{ name: 'kernel6.18', platform: 'amzn2023', advisories: [{ id: 'ALAS2023-1', url: 'https://alas.aws.amazon.com/x', release_date: '2026-10-24' }], status: 'Fixed', opt_in_repo: null }] }], meta: { cursor: null, backfill_complete: true, last_success_date: '2026-10-25', retry: [], index_total: 3 } });
  await h.run(T0);
  const issues = h.vulnIssues();
  assert.equal(issues.length, 1);
  assert.equal(issues[0].title, '[P1][demo] Amazon Linux 2023 のカーネル kernel6.18 の脆弱性 3件');
  assert.deepEqual(parseMarker(issues[0].body).mk, ['CVE-2026-0001', 'CVE-2026-0002', 'CVE-2026-0003']);
  assert.ok(!issues[0].labels.includes('fixed-in-repo'));
});
