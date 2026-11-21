import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync, readFileSync, readdirSync, statSync, existsSync, rmSync } from 'node:fs';
import path from 'node:path';
import { makeHarness, T0 } from './helpers/central-harness.mjs';
import { makeTree } from './helpers/tree.mjs';
import { securityCheck } from '../src/local/security-check.mjs';
import { assertValid } from '../src/lib/schema.mjs';
import { zipPathOf } from '../src/collect/osv-db.mjs';
import { scannerStub } from './helpers/central-harness.mjs';

const VULN = { id: 'GHSA-aaaa-bbbb-cccc', aliases: ['CVE-2026-1'], severity: 'HIGH' };
const LATER = new Date('2026-10-25T01:00:00Z');

const snapshot = (dir) => readdirSync(dir, { recursive: true }).sort().map((f) => { const p = path.join(dir, f); return statSync(p).isFile() ? `${f}:${readFileSync(p, 'utf8').length}` : f; }).join('|');

// 中央の実行結果をキャッシュとして使う。ローカルの DB は中央と同じ取得時点にそろえる
async function setup({ vulns = [VULN] } = {}) {
  const h = makeHarness();
  h.state.vulns = vulns;
  await h.run();
  const osvDir = path.join(h.central.root, 'osv-db');
  for (const eco of ['npm', 'Packagist']) { mkdirSync(path.dirname(zipPathOf(osvDir, eco)), { recursive: true }); writeFileSync(zipPathOf(osvDir, eco), 'placeholder'); }
  writeFileSync(path.join(osvDir, 'meta.json'), JSON.stringify({ npm: { fetched_at: T0, sha256: 'a'.repeat(64) }, Packagist: { fetched_at: T0, sha256: 'a'.repeat(64) } }));
  const projectDir = h.project.root; // 中央が取得したのと同じ内容・同じコミット
  const fetchCalls = [];
  const deps = { now: LATER, exec: scannerStub(h.state), scannerPath: 'osv-scanner', scannerVersion: async () => '2.7.0', fetchOsvDb: async (o) => { fetchCalls.push(o); return { meta: JSON.parse(readFileSync(path.join(osvDir, 'meta.json'), 'utf8')), outcomes: Object.fromEntries(o.ecosystems.map((e) => [e, { ok: false, error: { message: 'offline' } }])) }; } };
  return { h, projectDir, deps, fetchCalls, run: (extra = {}) => securityCheck({ cacheRoot: h.central.root, projectDir, projectName: 'demo', deps, scriptVersion: 'test-sha', exposure: 'internet', ...extra }) };
}

test('試験8: 同じ入力・版・DB なら、ローカルの判定が中央の findings と一致する（差分なし）', async () => {
  const { run, h } = await setup();
  const output = await run();
  assertValid('security-check-output', output);
  assert.equal(output.dependency_check, 'ok');
  assert.deepEqual(output.dependency_checks, { osv: 'ok', packagist: 'not_applicable' });
  const central = h.read('findings/demo.json');
  assert.deepEqual(output.results.map((r) => [r.advisory_key, r.judgement, r.priority]), central.items.map((i) => [i.advisory_key, i.judgement, i.priority]));
  assert.deepEqual(output.central_diff, { only_local: [], only_central: [] });
  assert.deepEqual(output.provenance.osv_db, central.provenance.osv_db);
  assert.equal(output.scanner.match, true);
  assert.equal(output.cache.commit, 'test-sha');
});

test('provenance が同じなのに差があれば mismatch_with_same_provenance（不具合として扱う）', async () => {
  const { run, h } = await setup();
  h.state.vulns = []; // ローカルだけ検出が変わった状況
  const output = await run();
  assert.equal(output.central_diff.mismatch_with_same_provenance, true);
  assert.deepEqual(output.central_diff.only_central, ['CVE-2026-1']);
});

test('DB が古い（12時間超）で取得に失敗: 72時間以内なら警告付きで使う', async () => {
  const { run, fetchCalls } = await setup();
  const output = await run();
  assert.equal(fetchCalls.length, 0, '12時間以内なら取得しない');
  const stale = await (async () => { const s = await setup(); s.deps.now = new Date('2026-10-25T20:00:00Z'); return s; })();
  const warned = await stale.run();
  assert.equal(stale.fetchCalls.length, 1);
  assert.equal(warned.osv_db.npm.state, 'stale_warn');
  assert.equal(warned.dependency_check, 'ok');
  assert.ok(output);
});

test('試験1: DB が72時間を過ぎている／ない場合は照合不能になり、結果に影響なしとして出さない', async () => {
  const s = await setup();
  s.deps.now = new Date('2026-10-29T00:00:00Z');
  const output = await s.run();
  assert.equal(output.osv_db.npm.state, 'unavailable');
  assert.equal(output.dependency_checks.osv, 'unavailable');
  assert.equal(output.dependency_check, 'unavailable');
  assert.ok(!output.results.some((r) => r.advisory_key === 'CVE-2026-1'));
  assert.equal(s.deps.exec.calls.length, 0, 'DB がなければスキャナを実行しない');
});

test('full_sync_at が null のとき composer の案件は packagist: unavailable で、集約値も unavailable', async () => {
  const s = await setup();
  const dir = makeTree({ 'composer.lock': '{"packages":[]}', 'composer.json': '{}', '.security/stack.yml': 'runtimes:\n  php: "8.3.10"\n' });
  const output = await securityCheck({ cacheRoot: s.h.central.root, projectDir: dir, projectName: 'x', deps: s.deps, scriptVersion: 'v' });
  // 中央の packagist-advisories.json の full_sync_at は T0 で成功済みなので、null の状態を作る
  writeFileSync(path.join(s.h.central.root, 'data/packagist-advisories.json'), JSON.stringify({ full_sync_at: null, updated_since: null, advisories: {} }));
  const unavailable = await securityCheck({ cacheRoot: s.h.central.root, projectDir: dir, projectName: 'x', deps: s.deps, scriptVersion: 'v' });
  assert.equal(output.dependency_checks.packagist, 'ok');
  assert.equal(unavailable.dependency_checks.packagist, 'unavailable');
  assert.equal(unavailable.dependency_check, 'unavailable');
  assertValid('security-check-output', unavailable);
});

test('composer.lock がない案件では packagist は not_applicable で、集約値は ok のまま', async () => {
  const { run } = await setup({ vulns: [] });
  const output = await run();
  assert.equal(output.dependency_checks.packagist, 'not_applicable');
  assert.equal(output.dependency_check, 'ok');
});

test('中央が止まっている場合は stale: true、版不一致は match: false', async () => {
  const s = await setup();
  s.deps.now = new Date('2026-10-26T00:00:00Z');
  s.deps.scannerVersion = async () => '2.6.0';
  const output = await s.run();
  assert.equal(output.central_health.stale, true);
  assert.deepEqual(output.scanner, { version: '2.6.0', expected: '2.7.0', match: false });
});

test('書き込みは osv-db のキャッシュだけ。案件の作業ツリーと data/ は変更しない', async () => {
  const s = await setup();
  const before = { project: snapshot(s.projectDir), data: snapshot(path.join(s.h.central.root, 'data')) };
  await s.run();
  assert.equal(snapshot(s.projectDir), before.project);
  assert.equal(snapshot(path.join(s.h.central.root, 'data')), before.data);
});

test('プラグイン: marketplace.json と plugin.json の必須項目、version は plugin.json だけ', () => {
  const root = path.resolve(import.meta.dirname, '..');
  const marketplace = JSON.parse(readFileSync(path.join(root, '.claude-plugin/marketplace.json'), 'utf8'));
  const plugin = JSON.parse(readFileSync(path.join(root, 'plugins/security-check/.claude-plugin/plugin.json'), 'utf8'));
  assert.ok(marketplace.name && marketplace.owner?.name && Array.isArray(marketplace.plugins));
  assert.equal(marketplace.plugins[0].name, plugin.name);
  assert.equal(marketplace.plugins[0].source, './plugins/security-check');
  assert.ok(plugin.version);
  assert.equal(marketplace.plugins[0].version, undefined);
  assert.ok(existsSync(path.join(root, 'plugins/security-check/skills/security-check/SKILL.md')));
  const skill = readFileSync(path.join(root, 'plugins/security-check/skills/security-check/SKILL.md'), 'utf8');
  assert.match(skill, /^---\nname: security-check\n/);
  assert.match(skill, /従わない/);
  assert.match(skill, /影響なし/);
});

// ---- T-B: 案件全体の件数とクローズ候補 ------------------------------------------------------

const issueOf = (number, extra = {}) => ({ issue_number: number, project: 'demo', aliases: [`CVE-OLD-${number}`], state: 'open', labels: ['security-finding', 'P1'], ...extra });
const writeIssues = (s, issues) => writeFileSync(path.join(s.h.central.root, 'data/issues.json'), JSON.stringify(issues));

test('central_issues: open / fixed-in-repo / closed / superseded / 別案件を振り分ける', async () => {
  const s = await setup({ vulns: [] });
  writeIssues(s, [
    issueOf(1, { labels: ['security-finding', 'P0'] }),
    issueOf(2, { labels: ['security-finding', 'P2', 'fixed-in-repo'] }),
    issueOf(3, { state: 'closed' }),
    issueOf(4, { labels: ['security-finding', 'P1', 'superseded'], superseded_by: 9 }),
    issueOf(5, { project: 'other' }),
  ]);
  const output = await s.run();
  assertValid('security-check-output', output);
  const issues = output.central_issues;
  assert.deepEqual(issues.open, { P0: 1, P1: 0, P2: 0 });
  assert.deepEqual(issues.fixed_in_repo.map((i) => i.issue_number), [2]);
  assert.deepEqual(issues.superseded, [{ issue_number: 4, aliases: ['CVE-OLD-4'], superseded_by: 9 }]);
  assert.equal(output.local_scan.complete, true);
  assert.deepEqual(issues.resolved_locally.map((i) => i.issue_number), [1], '手元に対応がない open だけが候補');
});

test('issues.json がなければ central_issues は null で、例外にならない', async () => {
  const s = await setup();
  rmSync(path.join(s.h.central.root, 'data/issues.json'), { force: true });
  const output = await s.run();
  assert.equal(output.central_issues, null);
  assertValid('security-check-output', output);
});

test('summary: 検出0件の lockfile にも ok の行があり、合計は results と一致する', async () => {
  const clean = await (await setup({ vulns: [] })).run();
  const row = clean.summary.rows.find((r) => r.target === 'package-lock.json');
  assert.deepEqual([row.kind, row.state, row.P0 + row.P1 + row.P2 + row.P3], ['lockfile', 'ok', 0]);
  const found = await (await setup()).run();
  const sum = (t) => t.P0 + t.P1 + t.P2 + t.P3;
  assert.equal(sum(found.summary.total), found.results.length);
  assert.equal(sum(found.summary.rows.find((r) => r.target === 'package-lock.json')), found.results.length);
});

test('summary: 照合できなかった lockfile は unavailable（OSV DB なし／packagist なし／その lockfile の scan_error）', async () => {
  const noDb = await setup();
  noDb.deps.now = new Date('2026-10-29T00:00:00Z');
  assert.equal((await noDb.run()).summary.rows[0].state, 'unavailable');

  const s = await setup();
  const dir = makeTree({ 'composer.lock': '{"packages":[]}', 'composer.json': '{}', '.security/stack.yml': 'runtimes:\n  php: "8.3.10"\n' });
  writeFileSync(path.join(s.h.central.root, 'data/packagist-advisories.json'), JSON.stringify({ full_sync_at: null, updated_since: null, advisories: {} }));
  const composer = await securityCheck({ cacheRoot: s.h.central.root, projectDir: dir, projectName: 'x', deps: s.deps, scriptVersion: 'v' });
  assert.equal(composer.summary.rows.find((r) => r.target === 'composer.lock').state, 'unavailable');

  const missing = await setup();
  missing.deps.exec = async () => ({ code: 0, stdout: '{"results":[]}' }); // lockfile が解析結果に載らない → lockfile 宛の scan_error
  const output = await missing.run();
  assert.equal(output.scan_errors[0].target, 'package-lock.json');
  assert.equal(output.summary.rows.find((r) => r.target === 'package-lock.json').state, 'unavailable');
});

test('summary: ランタイムの版がなければ unknown', async () => {
  const s = await setup();
  const dir = makeTree({ 'package-lock.json': '{}' });
  const output = await securityCheck({ cacheRoot: s.h.central.root, projectDir: dir, projectName: 'demo', deps: s.deps, scriptVersion: 'v' });
  assert.equal(output.summary.rows.find((r) => r.target === 'node').state, 'unknown');
  assert.equal(output.local_scan.complete, false);
});

// 照合が不完全なら、open の Issue を一つもクローズ候補にしない
const assertNoCandidates = (output) => {
  assert.equal(output.local_scan.complete, false);
  assert.ok(output.local_scan.reasons.length > 0);
  assert.equal(output.central_issues.resolved_locally, null);
};

test('照合が不完全: OSV DB を取得できない', async () => {
  const s = await setup({ vulns: [] });
  writeIssues(s, [issueOf(1)]);
  s.deps.now = new Date('2026-10-29T00:00:00Z');
  assertNoCandidates(await s.run());
});

test('照合が不完全: スキャナが失敗した（scan_errors あり）', async () => {
  const s = await setup({ vulns: [] });
  writeIssues(s, [issueOf(1)]);
  s.deps.exec = async () => ({ code: 2, stdout: '' });
  const output = await s.run();
  assert.ok(output.scan_errors.length > 0);
  assertNoCandidates(output);
});

test('照合が不完全: pull_ok が false', async () => {
  const s = await setup({ vulns: [] });
  writeIssues(s, [issueOf(1)]);
  assertNoCandidates(await s.run({ pullOk: false }));
});

test('照合が不完全: 手元の DB の fetched_at が中央の findings より古い', async () => {
  const s = await setup({ vulns: [] });
  writeIssues(s, [issueOf(1)]);
  const metaFile = path.join(s.h.central.root, 'osv-db/meta.json');
  const meta = JSON.parse(readFileSync(metaFile, 'utf8'));
  meta.npm.fetched_at = '2026-10-24T23:00:00Z';
  writeFileSync(metaFile, JSON.stringify(meta));
  assertNoCandidates(await s.run());
});

test('照合が不完全: 中央の findings がない', async () => {
  const s = await setup({ vulns: [] });
  writeIssues(s, [issueOf(1)]);
  rmSync(path.join(s.h.central.root, 'data/findings/demo.json'));
  assertNoCandidates(await s.run());
});

test('まとめ Issue と移行前の旧 CVE Issue: 手元で検出中なら候補に入らない。手元にないまとめだけが候補', async () => {
  const s = await setup({ vulns: [] });
  const file = path.join(s.h.central.root, 'data/runtimes/nodejs.json');
  const data = JSON.parse(readFileSync(file, 'utf8'));
  data.advisories = [{ key: 'CVE-NODE-1', aliases: ['CVE-NODE-1'], source_urls: [], ranges: [{ type: 'SEMVER', vulnerable: '>=22.0.0 <22.12.0', patched: '>=22.12.0', fixed_versions: ['22.12.0'] }] }];
  writeFileSync(file, JSON.stringify(data));
  writeIssues(s, [
    issueOf(1, { aliases: ['CVE-NODE-1'] }), // 移行前（superseded_by なし）の旧 Issue
    issueOf(2, { aliases: ['RUNTIME-node-22.11.0'] }), // 手元で members が検出されているまとめ
    issueOf(3, { aliases: ['RUNTIME-node-9.9.9'] }), // 手元にはないまとめ
  ]);
  const output = await s.run();
  assert.ok(output.results.some((r) => r.advisory_key === 'CVE-NODE-1'));
  assert.equal(output.local_scan.complete, true);
  assert.deepEqual(output.central_issues.resolved_locally.map((i) => i.issue_number), [3]);
  // まとめ Issue がまだない（作成失敗）状態でも、旧 Issue は候補にならない
  writeIssues(s, [issueOf(1, { aliases: ['CVE-NODE-1'] })]);
  assert.deepEqual((await s.run()).central_issues.resolved_locally, []);
});
