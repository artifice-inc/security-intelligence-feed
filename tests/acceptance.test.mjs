import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { makeHarness, failing, T0, T1 } from './helpers/central-harness.mjs';
import { validateOutDir } from '../src/publish/validate-out.mjs';
import { guardCommit, GuardError } from '../src/publish/guard-commit.mjs';
import { exportInventory } from '../src/inventory/export-inventory.mjs';
import { makeTree, makeCentralRepo } from './helpers/tree.mjs';

const VULN = { id: 'GHSA-aaaa-bbbb-cccc', aliases: ['CVE-2026-1'], severity: 'HIGH' };

test('通常の検出: Issue 起票・data のコミット・完了通知・スキーマ適合（success）', async () => {
  const h = makeHarness();
  h.state.vulns = [VULN];
  const outcome = await h.run();
  assert.equal(outcome.status, 'success', JSON.stringify(outcome.reasons));
  assert.equal(outcome.committed, true);
  assert.equal(h.state.heartbeats, 1);
  assert.equal(h.vulnIssues().length, 1);
  assert.equal(h.vulnIssues()[0].title, '[P1][demo] CVE-2026-1 example-package');
  const findings = h.read('findings/demo.json');
  assert.equal(findings.scan_status, 'complete');
  assert.equal(findings.items[0].issue_number, 1);
  assert.equal(h.read('health.json').last_run.status, 'success');
  assert.equal(h.read('health.json').last_success_at, T0);
  assert.equal(h.read('issues.json')[0].issue_number, 1);
  assert.match(readFileSync(path.join(h.central.root, 'data/digest/latest.md'), 'utf8'), /\| demo \|/);
  assert.deepEqual(validateOutDir(path.join(h.central.root, 'data')), []);
  assert.equal(h.central.remoteCount(), 2, 'push まで完了している');
  assert.equal(h.api.issues.size, 1, '正常な回に health Issue は作られない');
});

test('冪等性: 同じ入力で2回目は Issue への書き込み 0 件、git の差分も 0 件', async () => {
  const h = makeHarness();
  h.state.vulns = [VULN];
  await h.run();
  const commits = h.central.commitCount();
  h.api.resetWrites();
  const second = await h.run();
  assert.equal(second.status, 'success');
  assert.equal(h.api.writeCount, 0);
  assert.equal(second.committed, false);
  assert.equal(h.central.commitCount(), commits);
});

test('D1: 起票の後に push が失敗しても、次回の実行で Issue が重複しない', async () => {
  const h = makeHarness();
  h.state.vulns = [VULN];
  h.state.pushFails = true;
  const failed = await h.run();
  assert.equal(failed.status, 'failed');
  assert.equal(h.state.heartbeats, 0, '完了通知は success のときだけ');
  assert.equal(h.vulnIssues().length, 1);
  assert.equal(h.central.remoteCount(), 1, 'push されていない');
  assert.ok([...h.api.issues.values()].some((i) => i.labels.includes('health')), 'push 失敗は health Issue に記録される');
  h.central.git('reset', '-q', '--hard', 'origin/main'); // 失敗した回のローカルコミットを捨てる（Actions では環境ごと消える）
  h.state.pushFails = false;
  const next = await h.run(T1);
  assert.equal(next.status, 'success', JSON.stringify(next.reasons));
  assert.equal(h.vulnIssues().length, 1);
  assert.equal(h.read('findings/demo.json').items[0].issue_number, 1);
  assert.equal(h.api.closeCalls.length, 1, '復旧で health Issue が自動クローズされる');
});

test('段6: 1回目のスキーマ検証に失敗した回は、コミットも脆弱性 Issue の操作もしない（health Issue だけ更新）', async () => {
  const h = makeHarness();
  h.state.vulns = [VULN];
  mkdirSync(path.join(h.central.root, 'data/advisories'), { recursive: true });
  writeFileSync(path.join(h.central.root, 'data/advisories/broken.json'), '{"key": 1}');
  h.central.git('add', '-A');
  h.central.git('commit', '-q', '-m', 'broken');
  const commits = h.central.commitCount();
  const outcome = await h.run();
  assert.equal(outcome.status, 'failed');
  assert.equal(h.vulnIssues().length, 0);
  assert.equal(h.central.commitCount(), commits);
  assert.equal(h.state.heartbeats, 0);
  assert.ok([...h.api.issues.values()].every((i) => i.labels.includes('health')));
  assert.equal(h.api.issues.size, 1);
});

test('段8b: reconcile の後の issue_number が不正だとコミットも完了通知もされず、Issue 操作は次回に引き継がれる', async () => {
  const h = makeHarness();
  h.state.vulns = [VULN];
  const realCreate = h.api.createIssue.bind(h.api);
  h.api.createIssue = async (data) => { const created = await realCreate(data); return data.labels.includes('health') ? created : { ...created, number: 'not-a-number' }; };
  const commits = h.central.commitCount();
  const outcome = await h.run();
  assert.equal(outcome.status, 'failed');
  assert.match(outcome.reasons.join(), /最終/);
  assert.equal(h.central.commitCount(), commits);
  assert.equal(h.state.heartbeats, 0);
  h.api.createIssue = realCreate;
  const next = await h.run(T1);
  assert.equal(next.status, 'success', JSON.stringify(next.reasons));
  assert.equal(h.vulnIssues().length, 1, '重複しない');
});

test('段8b: health.json だけが不正でもコミットされない', async () => {
  const h = makeHarness();
  h.state.osvMeta = { fetched_at: T0 }; // sha256 が欠けた不正な値は health.json にだけ入る
  const commits = h.central.commitCount();
  const outcome = await h.run();
  assert.equal(outcome.status, 'failed');
  assert.equal(h.central.commitCount(), commits);
  assert.equal(h.state.heartbeats, 0);
});

test('guard-commit: data/ 以外に変更があると中止する', async () => {
  const c = makeCentralRepo();
  writeFileSync(path.join(c.root, 'src-change.txt'), 'x');
  const out = path.join(c.root, '.work/out/data');
  mkdirSync(out, { recursive: true });
  writeFileSync(path.join(out, 'health.json'), '{}');
  await assert.rejects(() => guardCommit({ repoDir: c.root, outDataDir: out, message: 'm' }), GuardError);
  assert.equal(c.commitCount(), 1);
});

test('guard-commit: 差分がなければコミットしない。inventory-export は同期で消さない', async () => {
  const c = makeCentralRepo();
  const out = path.join(c.root, '.work/out/data');
  mkdirSync(path.join(c.root, 'data/inventory-export/x'), { recursive: true });
  writeFileSync(path.join(c.root, 'data/inventory-export/x/manifest.json'), '{}');
  c.git('add', '-A'); c.git('commit', '-q', '-m', 'export');
  mkdirSync(out, { recursive: true });
  writeFileSync(path.join(out, '.gitkeep'), ''); // 実際の実行では data/ をそのまま out へ複製してある
  const result = await guardCommit({ repoDir: c.root, outDataDir: out, message: 'm' });
  assert.equal(result.committed, false);
  assert.equal(readFileSync(path.join(c.root, 'data/inventory-export/x/manifest.json'), 'utf8'), '{}');
});

test('試験2/2b: 情報源が1つ失敗した回は partial。前回の findings が残り、fixed-in-repo は付かず、完了通知もない', async () => {
  const h = makeHarness();
  h.state.vulns = [VULN];
  await h.run();
  h.state.vulns = []; // lockfile は修正版に更新された
  h.state.collectors.kev = failing();
  const outcome = await h.run(T1);
  assert.equal(outcome.status, 'partial');
  const findings = h.read('findings/demo.json');
  assert.equal(findings.scan_status, 'partial');
  assert.equal(findings.items.length, 1);
  assert.equal(findings.items[0].locations[0].last_confirmed_at, T0);
  assert.ok(!h.vulnIssues()[0].labels.includes('fixed-in-repo'));
  assert.equal(h.state.heartbeats, 1, '1回目の success だけ');
  assert.ok([...h.api.issues.values()].some((i) => i.labels.includes('health')));
  assert.equal(h.read('health.json').sources.kev.last_success_at, T0);
  assert.equal(h.read('health.json').last_success_at, T0, 'partial では last_success_at を更新しない');
});

test('complete の回に消えた項目だけが解消になり、fixed-in-repo が付く（クローズはされない）', async () => {
  const h = makeHarness();
  h.state.vulns = [VULN];
  await h.run();
  h.state.vulns = [];
  const outcome = await h.run(T1);
  assert.equal(outcome.status, 'success');
  assert.ok(h.vulnIssues()[0].labels.includes('fixed-in-repo'));
  assert.equal(h.vulnIssues()[0].state, 'open');
  assert.equal(h.read('findings/demo.json').items.length, 0);
});

test('試験3: 監視ブランチ（master）で未修正なら、他のブランチが修正済みでも Issue は open のまま', async () => {
  const h = makeHarness();
  h.state.vulns = [VULN];
  await h.run();
  // master は同じ内容のまま。別ブランチの変更は取得対象に入らない
  await h.run(T1);
  assert.ok(!h.vulnIssues()[0].labels.includes('fixed-in-repo'));
  assert.equal(h.vulnIssues()[0].state, 'open');
});

test('D6: 案件の取得に失敗した回は依存関係を照合せず、findings と根拠が残り、ランタイムは照合し直される', async () => {
  const h = makeHarness();
  h.state.vulns = [VULN];
  await h.run();
  h.state.vulns = []; // 取得できていれば解消扱いになる状況
  h.state.cloneUrl = () => '/nonexistent/repo';
  h.state.collectors['node-core'] = async () => ({ ok: true, records: [{ id: '9', sha: 's', cve: ['CVE-2026-777'], vulnerable: '22.x', patched: '^22.23.4', severity: 'high', ref: 'https://nodejs.org/x', description: 'node bug' }], unchanged: [] });
  const outcome = await h.run(T1);
  assert.equal(outcome.status, 'partial');
  const findings = h.read('findings/demo.json');
  assert.equal(findings.inventory_status, 'unavailable');
  assert.equal(findings.scan_status, 'partial');
  assert.ok(findings.scan_errors.some((e) => e.kind === 'inventory'));
  const dep = findings.items.find((i) => i.advisory_key === 'CVE-2026-1');
  assert.equal(dep.locations[0].last_confirmed_at, T0, '依存関係は確認し直していない');
  const runtime = findings.items.find((i) => i.advisory_key === 'CVE-2026-777');
  assert.equal(runtime.locations[0].last_confirmed_at, T1, 'ランタイムは前回のインベントリで照合し直される');
  assert.ok(!h.vulnIssues().some((i) => i.labels.includes('fixed-in-repo')));
  assert.match(readFileSync(path.join(h.central.root, 'data/digest/latest.md'), 'utf8'), /unavailable/);
});

test('OSV の DB を取得できなかった回は partial（試験1）', async () => {
  const h = makeHarness();
  h.state.osvOk = { npm: false, Packagist: true, PyPI: true };
  const outcome = await h.run();
  assert.equal(outcome.status, 'partial');
  assert.equal(h.read('findings/demo.json').scan_status, 'partial');
  assert.equal(h.deps.exec.calls.length, 0, 'DB がなければスキャナを実行せず、影響なしとも表示しない');
});

test('export 方式: 申告された PHP / Node の脆弱性と EOL を検出し、版が不明なら RUNTIME-UNKNOWN（P3）', async () => {
  const known = makeTree({ '.security/stack.yml': 'runtimes:\n  php: "8.3.10"\n  node: "18.19.0"\n', 'composer.lock': '{"packages":[]}', 'package-lock.json': '{}' });
  const unknown = makeTree({ 'composer.lock': '{"packages":[]}', 'package-lock.json': '{}' });
  const projects = { project_owner: 'o', projects: [
    { project: 'exp-known', source: 'export', monitor_ref: 'main', owners: ['alice'], exposure: 'internet' },
    { project: 'exp-unknown', source: 'export', monitor_ref: 'main', owners: ['alice'], exposure: 'internal' },
  ] };
  const h = makeHarness({ projects });
  for (const [name, dir] of [['exp-known', known], ['exp-unknown', unknown]]) {
    exportInventory({ projectDir: dir, project: name, outDir: path.join(h.central.root, 'data/inventory-export', name), now: T0, sourceRef: 'main', sourceCommit: 'abc' });
  }
  h.central.git('add', '-A'); h.central.git('commit', '-q', '-m', 'exports'); h.central.git('push', '-q');
  h.state.collectors['php-ghsa'] = async () => ({ ok: true, records: [{ ghsa_id: 'GHSA-phpp-aaaa-bbbb', cve_id: 'CVE-2026-93682', published_at: null, updated_at: null, withdrawn_at: null, severity: 'high', summary: 'php bug', html_url: 'https://github.com/php/php-src/security/advisories/GHSA-phpp-aaaa-bbbb', vulnerabilities: [{ package: 'ext-standard', vulnerable_version_range: '<8.3.12', patched_versions: '8.3.12', parsed: [{ type: 'PHP_BRANCH', branch: '8.3', fixed: '8.3.12' }] }] }] });
  h.state.collectors['php-releases'] = async () => ({ ok: true, records: [{ type: 'branch', branch: '8.3', state: 'security', security_support_end: '2027-12-31', active_support_end: null }] });
  const outcome = await h.run();
  const known1 = h.read('findings/exp-known.json');
  assert.equal(known1.inventory_status, 'fresh');
  const keys = known1.items.map((i) => i.advisory_key);
  assert.ok(keys.includes('CVE-2026-93682'), `PHP の脆弱性を検出する: ${keys}`);
  assert.ok(keys.includes('EOL-node-18'), 'Node 18 の EOL を検出する');
  assert.equal(known1.items.find((i) => i.advisory_key === 'EOL-node-18').priority, 'P2');
  const unknown1 = h.read('findings/exp-unknown.json');
  assert.deepEqual(unknown1.items.map((i) => [i.advisory_key, i.priority]).sort(), [['RUNTIME-UNKNOWN-node', 'P3'], ['RUNTIME-UNKNOWN-php', 'P3']]);
  assert.ok(outcome.status);
  assert.ok(h.vulnIssues().every((i) => !i.title.includes('RUNTIME-UNKNOWN')), 'P3 は Issue にしない');
});

test('Packagist: 後から追加したパッケージの既存の脆弱性が、差分が空でも検出される。差分が空でも解消扱いにならない', async () => {
  const h = makeHarness({ projectFiles: { 'composer.lock': '{"packages":[{"name":"other/pkg","version":"1.0.0"}]}', 'composer.json': '{}', '.security/stack.yml': 'runtimes:\n  php: "8.3.10"\n' } });
  const oldAdvisory = { advisoryId: 'PKSA-old', packageName: 'acme/lib', affectedVersions: '<2.0.0', cve: 'CVE-2026-55', title: 'old', link: 'https://example.test/p', reportedAt: '2020-01-01 00:00:00', sources: [{ name: 'FriendsOfPHP/security-advisories', remoteId: 'x' }], remoteId: 'x' };
  let call = 0;
  h.state.collectors.packagist = async ({ updatedSince }) => { call += 1; return { ok: true, records: updatedSince === 0 ? [oldAdvisory] : [] }; };
  const first = await h.run();
  assert.equal(h.read('packagist-advisories.json').full_sync_at, T0);
  assert.equal(h.read('findings/demo.json').items.filter((i) => i.advisory_key === 'PKSA-old' || i.advisory_key === 'CVE-2026-55').length, 0);
  const { updateRepo } = await import('./helpers/tree.mjs');
  updateRepo(h.project, { 'composer.lock': '{"packages":[{"name":"other/pkg","version":"1.0.0"},{"name":"acme/lib","version":"1.9.0"}]}' }, 'master');
  const second = await h.run(T1);
  assert.ok(call >= 2);
  const items = h.read('findings/demo.json').items.filter((i) => i.aliases.includes('PKSA-old'));
  assert.equal(items.length, 1, JSON.stringify(second.reasons));
  const third = await h.run('2026-10-25T18:00:00Z');
  assert.equal(h.read('findings/demo.json').items.filter((i) => i.aliases.includes('PKSA-old')).length, 1, '差分が空でも消えない');
  assert.ok(first && third);
});

test('Packagist: 全件取得がまだ成功していない間は composer の案件が complete にならない', async () => {
  const h = makeHarness({ projectFiles: { 'composer.lock': '{"packages":[]}', 'composer.json': '{}', '.security/stack.yml': 'runtimes:\n  php: "8.3.10"\n' } });
  h.state.collectors.packagist = failing();
  const outcome = await h.run();
  assert.equal(outcome.status, 'partial');
  assert.equal(h.read('findings/demo.json').scan_status, 'partial');
  assert.equal(h.read('packagist-advisories.json').full_sync_at, null);
});

test('health Issue: 異常があれば起票され、復旧したら自動でクローズされる（脆弱性の Issue は閉じない）', async () => {
  const h = makeHarness();
  h.state.vulns = [VULN];
  h.state.collectors.kev = failing();
  await h.run();
  const health = [...h.api.issues.values()].filter((i) => i.labels.includes('health'));
  assert.equal(health.length, 1);
  assert.equal(health[0].title, '[health] 収集・照合の異常');
  h.state.collectors.kev = failing();
  await h.run(T1);
  assert.equal([...h.api.issues.values()].filter((i) => i.labels.includes('health')).length, 1, '常に最大1件');
  h.state.collectors.kev = undefined;
  h.state.collectors = { ...h.state.collectors, kev: async () => ({ ok: true, records: [] }) };
  await h.run('2026-10-26T00:00:00Z');
  assert.deepEqual(h.api.closeCalls, [health[0].number]);
  assert.ok(h.vulnIssues().every((i) => i.state === 'open'));
});

test('M2b: feed-state.json と新しい項目を含む data/ でも起動の検証を通る', async () => {
  const h = makeHarness();
  h.state.vulns = [VULN];
  await h.run();
  const dataDir = path.join(h.central.root, 'data');
  writeFileSync(path.join(dataDir, 'feed-state.json'), JSON.stringify({ mode: 'match', last_validated: null, digest_jp: { feed_sha: 'abc', keys: ['k'] }, cutover_data_commit: null }));
  const findingsPath = path.join(dataDir, 'findings/demo.json');
  const findings = JSON.parse(readFileSync(findingsPath, 'utf8'));
  findings.provenance.feed_version = 'abc';
  findings.items[0].priority_inputs = { kev: false };
  findings.items[0].priority_note = 'note';
  writeFileSync(findingsPath, JSON.stringify(findings));
  assert.deepEqual(validateOutDir(dataDir), []);
  const outcome = await h.run('2026-10-25T09:00:00Z');
  assert.ok(!outcome.reasons.some((r) => r.includes('前回までのデータ')), JSON.stringify(outcome.reasons));
});
