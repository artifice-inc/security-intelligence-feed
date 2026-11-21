import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { computePriority } from '../src/match/priority.mjs';
import { runOsvScan, buildScannerArgs } from '../src/match/osv-scan.mjs';
import { matchRuntimes } from '../src/match/runtime-match.mjs';
import { matchPackagist } from '../src/match/packagist-match.mjs';
import { assembleItems, buildAdvisoryIndex } from '../src/match/assemble.mjs';
import { matchProject } from '../src/match/match-project.mjs';
import { NOW, PROVENANCE, inventoryOf, inputsOf, scannerOutput, stubExec } from './helpers/match-fixtures.mjs';
import { writeFileSync } from 'node:fs';
import { loadRuntimeConditions } from '../src/lib/config.mjs';
import { assertValid } from '../src/lib/schema.mjs';

const root = mkdtempSync(path.join(tmpdir(), 'si-match-'));

test('優先度: P0〜P3 の表どおり', () => {
  assert.equal(computePriority({ judgement: 'affected', kev: true, severity: 'low', exposure: 'internal' }), 'P0');
  assert.equal(computePriority({ judgement: 'affected', kev: false, severity: 'High', exposure: 'internet' }), 'P1');
  assert.equal(computePriority({ judgement: 'affected', kev: false, severity: 'low', epssPercentile: 0.95, exposure: 'internet' }), 'P1');
  assert.equal(computePriority({ judgement: 'affected', kev: false, severity: 'critical', exposure: 'internal' }), 'P2');
  assert.equal(computePriority({ judgement: 'affected', kev: false, severity: null, epssPercentile: 0.94, exposure: 'internet' }), 'P2');
  assert.equal(computePriority({ judgement: 'needs_review', kev: true }), 'P3');
  assert.equal(computePriority({ judgement: 'not_affected' }), null);
});

test('osv-scan: 脆弱性ありの非0終了（1）はエラーではなく検出として扱う', async () => {
  const exec = stubExec(1, scannerOutput(root));
  const result = await runOsvScan({ exec, scannerPath: '/bin/osv-scanner', root, inputs: inputsOf(root, ['package-lock.json']), dbDir: '/db' });
  assert.equal(result.ok, true);
  assert.equal(result.detections.length, 1);
  assert.deepEqual(result.detections[0].fixed_versions, ['1.2.3']);
  assert.equal(result.detections[0].lockfile, 'package-lock.json');
  assert.deepEqual(result.detections[0].aliases, ['GHSA-aaaa-bbbb-cccc', 'CVE-2026-1']);
  const call = exec.calls[0];
  assert.ok(call.args.includes('--offline'));
  assert.equal(call.options.env.OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY, '/db');
  assert.ok(call.args.includes(`--lockfile=${path.join(root, 'package-lock.json')}`));
});

test('osv-scan: 終了コード0は検出なし。127は scanner エラー、128は lockfile エラー', async () => {
  const clean = await runOsvScan({ exec: stubExec(0, scannerOutput(root, [])), scannerPath: 'x', root, inputs: inputsOf(root, ['package-lock.json']), dbDir: '/db' });
  assert.equal(clean.ok, true);
  assert.equal(clean.detections.length, 0);
  const broken = await runOsvScan({ exec: stubExec(127, ''), scannerPath: 'x', root, inputs: inputsOf(root, ['package-lock.json']), dbDir: '/db' });
  assert.equal(broken.errors[0].kind, 'scanner');
  const none = await runOsvScan({ exec: stubExec(128, ''), scannerPath: 'x', root, inputs: inputsOf(root, ['package-lock.json']), dbDir: '/db' });
  assert.equal(none.errors[0].kind, 'lockfile');
});

test('osv-scan: JSON でない出力、結果に含まれない lockfile はエラー', async () => {
  assert.equal((await runOsvScan({ exec: stubExec(1, 'oops'), scannerPath: 'x', root, inputs: inputsOf(root, ['package-lock.json']), dbDir: '/db' })).errors[0].kind, 'scanner');
  const missing = await runOsvScan({ exec: stubExec(0, scannerOutput(root, [])), scannerPath: 'x', root, inputs: inputsOf(root, ['package-lock.json', 'apps/web/package-lock.json']), dbDir: '/db' });
  assert.deepEqual(missing.errors.map((e) => e.target), ['apps/web/package-lock.json']);
  assert.ok(buildScannerArgs({ inputs: [] }).includes('--format=json'));
});

test('osv-scan: --all-packages を付ける。脆弱性0件でも results に載る lockfile はエラーにならない', async () => {
  assert.ok(buildScannerArgs({ inputs: [] }).includes('--all-packages'));
  const listed = JSON.stringify({ results: [{ source: { path: path.join(root, 'package-lock.json'), type: 'lockfile' }, packages: [{ package: { name: 'p', version: '1.0.0', ecosystem: 'npm' } }] }] });
  const result = await runOsvScan({ exec: stubExec(0, listed), scannerPath: 'x', root, inputs: inputsOf(root, ['package-lock.json']), dbDir: '/db' });
  assert.equal(result.ok, true);
  assert.deepEqual(result.errors, []);
  assert.equal(result.detections.length, 0);
});

const runtimeData = {
  php: {
    branches: [{ branch: '8.2', state: 'security', is_eol: false, latest_version: '8.2.35' }, { branch: '7.4', state: 'eol', is_eol: true, latest_version: '7.4.33' }],
    advisories: [{ key: 'CVE-2026-93682', aliases: ['CVE-2026-93682', 'GHSA-7875-c8px-7q5f'], ranges: [{ type: 'PHP_BRANCH', branch: '8.2', fixed: '8.2.35' }, { type: 'PHP_BRANCH', branch: '8.3', fixed: '8.3.35' }], fixed_versions: [], source_urls: ['https://example.test/a'] }],
  },
  nodejs: {
    branches: [{ branch: '18', state: 'eol', is_eol: true, latest_version: '18.20.8' }, { branch: '22', state: 'lts', is_eol: false, latest_version: '22.23.4' }],
    advisories: [{ key: 'CVE-2026-111497', aliases: ['CVE-2026-111497', 'NODE-CORE-204'], ranges: [{ type: 'NODE_SEMVER', vulnerable: '22.x || 24.x', patched: '^22.23.4 || ^24.22.1', fixed_versions: ['22.23.4', '24.22.1'] }], fixed_versions: [], source_urls: [] }],
  },
};
const withRuntimes = (php, node, extraFiles = []) => inventoryOf({
  runtimes: { php: { version: null, constraint: null, source: null, ...php }, node: { version: null, constraint: null, source: null, ...node } },
  files: [{ path: 'composer.json', sha256: 'c'.repeat(64), kind: 'composer-json' }, { path: 'package.json', sha256: 'b'.repeat(64), kind: 'package-json' }, ...extraFiles],
});

test('runtime-match: PHP 8.2.34 は影響あり、8.2.35 とブランチ違いは影響なし', () => {
  const keys = (v) => matchRuntimes({ inventory: withRuntimes({ version: v, source: 'Dockerfile' }, { version: '22.23.4', source: '.nvmrc' }), runtimeData }).map((d) => d.advisory_key);
  assert.deepEqual(keys('8.2.34'), ['CVE-2026-93682']);
  assert.deepEqual(keys('8.2.35'), []);
  assert.deepEqual(keys('8.1.30'), []);
  const detection = matchRuntimes({ inventory: withRuntimes({ version: '8.2.34', source: 'Dockerfile' }, { version: '22.23.4', source: '.nvmrc' }), runtimeData })[0];
  assert.deepEqual(detection.fixed_versions, ['8.2.35']);
});

test('runtime-match: ブランチ付きの UNPARSED は同じブランチだけ needs_review。ブランチなしは全版 needs_review', () => {
  const ranges = [{ type: 'PHP_BRANCH', branch: '8.2', fixed: '8.2.20' }, { type: 'UNPARSED', branch: '8.0', raw: '8.0.2 - 8.0.30' }];
  const data = (r) => ({ php: { branches: [], advisories: [{ key: 'CVE-X', aliases: ['CVE-X'], ranges: r, fixed_versions: [], source_urls: [] }] }, nodejs: { branches: [], advisories: [] } });
  const judge = (v, r) => matchRuntimes({ inventory: withRuntimes({ version: v, source: 'Dockerfile' }, {}), runtimeData: data(r) })
    .filter((d) => d.advisory_key === 'CVE-X').map((d) => d.judgement);
  assert.deepEqual(judge('8.2.35', ranges), []);
  assert.deepEqual(judge('8.2.19', ranges), ['affected']);
  assert.deepEqual(judge('8.0.30', ranges), ['needs_review']);
  assert.deepEqual(judge('8.2.35', [{ type: 'UNPARSED', raw: '???' }]), ['needs_review']);
});

test('runtime-match: Node は vulnerable かつ patched 外のとき影響あり。EOL は P2 用の項目になる', () => {
  const inv = (v) => withRuntimes({}, { version: v, source: '.nvmrc' });
  const nodeKeys = (v) => matchRuntimes({ inventory: inv(v), runtimeData }).map((d) => d.advisory_key).filter((k) => k !== 'RUNTIME-UNKNOWN-php');
  assert.deepEqual(nodeKeys('22.23.3'), ['CVE-2026-111497']);
  assert.deepEqual(nodeKeys('22.23.4'), []);
  const eol = matchRuntimes({ inventory: inv('18.19.0'), runtimeData });
  assert.deepEqual(nodeKeys('18.19.0'), ['EOL-node-18']);
  const php = matchRuntimes({ inventory: withRuntimes({ version: '7.4.1', source: 'Dockerfile' }, {}), runtimeData });
  assert.ok(php.some((d) => d.advisory_key === 'EOL-php-7.4'));
});

test('runtime-match: 版が確定しなければ RUNTIME-UNKNOWN（needs_review）。関係ないランタイムは対象外', () => {
  const constraintOnly = matchRuntimes({ inventory: withRuntimes({ constraint: '>=8.1', source: 'composer.json' }, { version: '22.23.4', source: '.nvmrc' }), runtimeData });
  assert.deepEqual(constraintOnly.map((d) => [d.advisory_key, d.judgement]), [['RUNTIME-UNKNOWN-php', 'needs_review']]);
  const nothing = matchRuntimes({ inventory: withRuntimes({}, { version: '22.23.4', source: '.nvmrc' }), runtimeData });
  assert.ok(nothing.some((d) => d.advisory_key === 'RUNTIME-UNKNOWN-php'));
  const nodeOnly = inventoryOf({ files: [{ path: 'package-lock.json', sha256: 'a'.repeat(64), kind: 'lockfile' }], runtimes: { php: { version: null, constraint: null, source: null }, node: { version: '22.23.4', constraint: null, source: '.nvmrc' } } });
  assert.ok(!matchRuntimes({ inventory: nodeOnly, runtimeData }).some((d) => /php/.test(d.advisory_key)));
});

test('packagist-match: 全件の集合に対して判定する（後から追加したパッケージの既存の脆弱性も検出）', () => {
  const advisories = { 'PKSA-old': { packageName: 'acme/lib', affectedVersions: '<2.0.0', cve: 'CVE-2026-7', title: 'old record', link: 'https://example.test/p', reportedAt: '2026-01-01 00:00:00', sources: [] } };
  const composerLock = { packages: [{ name: 'acme/lib', version: '1.9.0' }], 'packages-dev': [{ name: 'other/dev', version: 'dev-main' }] };
  const found = matchPackagist({ composerLock, lockfile: 'composer.lock', advisories });
  assert.equal(found.length, 1);
  assert.deepEqual(found[0].fixed_versions, ['2.0.0']);
  assert.equal(found[0].judgement, 'affected');
  const unsupported = matchPackagist({ composerLock: { packages: [{ name: 'acme/lib', version: '1.2.3.4' }] }, lockfile: 'composer.lock', advisories });
  assert.equal(unsupported[0].judgement, 'needs_review');
  assert.equal(matchPackagist({ composerLock: { packages: [{ name: 'acme/lib', version: '2.0.0' }] }, lockfile: 'composer.lock', advisories }).length, 0);
});

test('assemble: 別名で同じ脆弱性は1件にまとまり、KEV で P0 になる', () => {
  const detections = [
    { lockfile: 'a/package-lock.json', package: 'p', ecosystem: 'npm', installed_version: '1.0.0', aliases: ['GHSA-x', 'CVE-1'], title: 't', judgement: 'affected', fixed_versions: ['1.0.1'], osv_id: 'GHSA-x', severity_hint: 'low' },
    { lockfile: 'b/package-lock.json', package: 'p', ecosystem: 'npm', installed_version: '1.1.0', aliases: ['CVE-1', 'GHSA-y'], title: 't', judgement: 'affected', fixed_versions: ['1.1.1'], osv_id: 'GHSA-y', severity_hint: 'low' },
  ];
  const advisory = { key: 'CVE-1', aliases: { cve: ['CVE-1'], ghsa: ['GHSA-x'], other: [] }, superseded_by: null, title: 'adv', severity: { level: 'low' }, known_exploited: { kev: true }, epss: {}, sources: [{ url: 'https://osv.dev/x', withdrawn_at: null }] };
  const items = assembleItems({ detections, index: buildAdvisoryIndex([advisory]), exposure: 'internet', now: NOW, provenance: PROVENANCE });
  assert.equal(items.length, 1);
  assert.equal(items[0].advisory_key, 'CVE-1');
  assert.equal(items[0].priority, 'P0');
  assert.equal(items[0].locations.length, 2);
  assert.deepEqual(items[0].fixed_versions, ['1.0.1', '1.1.1']);
});

test('matchProject: npm の検出とランタイムを統合し、dependency_checks を返す', async () => {
  const inventory = inventoryOf();
  const result = await matchProject({
    inventory, workdir: root, exec: stubExec(1, scannerOutput(root)), scannerPath: 'x', dbDir: '/db', osvAvailable: { npm: true, Packagist: true },
    runtimeData, packagistAdvisories: null, advisoryIndex: new Map(), provenance: PROVENANCE, now: NOW,
  });
  assert.deepEqual(result.dependency_checks, { osv: 'ok', packagist: 'not_applicable' });
  const dep = result.items.find((i) => i.advisory_key === 'CVE-2026-1');
  assert.equal(dep.priority, 'P1');
  assert.equal(dep.locations[0].installed_version, '1.2.0');
});

test('matchProject: DB が使えない / workdir なしなら unavailable で、検出も出さない', async () => {
  const inventory = inventoryOf();
  const exec = stubExec(1, scannerOutput(root));
  const noDb = await matchProject({ inventory, workdir: root, exec, scannerPath: 'x', dbDir: '/db', osvAvailable: { npm: false, Packagist: true }, runtimeData, packagistAdvisories: null, advisoryIndex: new Map(), provenance: PROVENANCE, now: NOW });
  assert.equal(noDb.dependency_checks.osv, 'unavailable');
  assert.equal(exec.calls.length, 0);
  assert.ok(!noDb.items.some((i) => i.advisory_key === 'CVE-2026-1'));
  const noWork = await matchProject({ inventory, workdir: null, exec, scannerPath: 'x', dbDir: '/db', osvAvailable: { npm: true, Packagist: true }, runtimeData, packagistAdvisories: null, advisoryIndex: new Map(), provenance: PROVENANCE, now: NOW });
  assert.equal(noWork.dependency_checks.osv, 'unavailable');
});

test('matchProject: composer.lock があり packagist の全件がなければ packagist は unavailable（試験: full_sync_at が null）', async () => {
  writeFileSync(path.join(root, 'composer.lock'), '{"packages":[{"name":"acme/lib","version":"1.9.0"}]}');
  const inventory = inventoryOf({ lockfiles: ['composer.lock'], files: [{ path: 'composer.lock', sha256: 'a'.repeat(64), kind: 'lockfile' }, { path: 'composer.json', sha256: 'a'.repeat(64), kind: 'composer-json' }] });
  const base = { inventory, workdir: root, exec: stubExec(0, JSON.stringify({ results: [{ source: { path: path.join(root, 'composer.lock'), type: 'lockfile' }, packages: [] }] })), scannerPath: 'x', dbDir: '/db', osvAvailable: { npm: true, Packagist: true }, runtimeData, advisoryIndex: new Map(), provenance: PROVENANCE, now: NOW };
  const without = await matchProject({ ...base, packagistAdvisories: null });
  assert.equal(without.dependency_checks.packagist, 'unavailable');
  const withSet = await matchProject({ ...base, packagistAdvisories: { advisories: { 'PKSA-1': { packageName: 'acme/lib', affectedVersions: '<2.0.0', cve: null, title: 't', link: null, reportedAt: null, sources: [] } } } });
  assert.equal(withSet.dependency_checks.packagist, 'ok');
  assert.ok(withSet.items.some((i) => i.advisory_key === 'PKSA-1'));
});

// ---- T-D: OS の条件と EOL ブランチ ----------------------------------------------------------

const osData = { php: { branches: [], advisories: [{ key: 'GHSA-win', aliases: ['GHSA-win', 'CVE-WIN-1'], ranges: [{ type: 'PHP_BRANCH', branch: '8.1', fixed: '8.1.29' }], fixed_versions: ['8.1.29'], source_urls: [] }] }, nodejs: { branches: [], advisories: [] } };
const osConditions = { php: { 'CVE-WIN-1': { os: ['windows'], note: 'Windows に限られる' } } };
const osMatch = (os) => matchRuntimes({ inventory: { ...withRuntimes({ version: '8.1.21', source: '.security/stack.yml' }, {}), os }, runtimeData: osData, conditions: osConditions }).find((d) => d.advisory_key === 'GHSA-win');

test('runtime-match: OS の条件あり・os=linux は needs_review（別名でも条件を引ける）', () => {
  const found = osMatch('linux');
  assert.equal(found.judgement, 'needs_review');
  assert.match(found.evidence, /Windows に限られる脆弱性。申告 os=linux/);
});

test('runtime-match: OS の条件あり・os 未申告は affected のままで、申告の案内が入る。os=windows も affected', () => {
  for (const os of [null, undefined]) {
    const found = osMatch(os);
    assert.equal(found.judgement, 'affected');
    assert.match(found.evidence, /stack\.yml に os を申告/);
  }
  const windows = osMatch('windows');
  assert.equal(windows.judgement, 'affected');
  assert.ok(!/申告/.test(windows.evidence));
});

test('config/runtime-conditions.json はスキーマに合い、CVE-2024-4577 を Windows に限っている', () => {
  const conditions = loadRuntimeConditions();
  assertValid('runtime-conditions', conditions);
  assert.deepEqual(conditions.php['CVE-2024-4577'].os, ['windows']);
});

const eolData = (advisoryOverrides = {}, branchOverrides = {}) => ({
  php: {
    branches: [{ branch: '8.1', state: 'eol', is_eol: true, security_support_end: '2025-12-31', latest_version: '8.1.34', ...branchOverrides }],
    advisories: [{ key: 'CVE-NEW', aliases: ['CVE-NEW'], ranges: [{ type: 'PHP_BRANCH', branch: '8.2', fixed: '8.2.30' }, { type: 'PHP_BRANCH', branch: '8.3', fixed: '8.3.30' }], fixed_versions: [], source_urls: [], published_at: '2026-10-21T13:34:25Z', ...advisoryOverrides }],
  },
  nodejs: { branches: [], advisories: [] },
});
const eolJudge = (data) => matchRuntimes({ inventory: withRuntimes({ version: '8.1.21', source: '.security/stack.yml' }, {}), runtimeData: data, conditions: {} })
  .filter((d) => d.advisory_key === 'CVE-NEW').map((d) => [d.judgement, d.evidence]);

test('runtime-match: EOL ブランチで、EOL 後に公開され範囲に出てこないアドバイザリは needs_review', () => {
  const [[judgement, evidence]] = eolJudge(eolData());
  assert.equal(judgement, 'needs_review');
  assert.equal(evidence, 'EOL のブランチ 8.1 は修正の対象外で、影響の有無を判定できません（公開 2026-10-21、8.1 のサポート終了 2025-12-31）');
});

test('runtime-match: 公開が EOL より前、published_at なし、サポート終了日なし、ブランチが EOL でない／範囲に 8.1 がある場合は今までどおり not_affected', () => {
  assert.deepEqual(eolJudge(eolData({ published_at: '2025-06-01T00:00:00Z' })), []);
  assert.deepEqual(eolJudge(eolData({ published_at: null })), []);
  assert.deepEqual(eolJudge(eolData({}, { security_support_end: null })), []);
  assert.deepEqual(eolJudge(eolData({}, { is_eol: false })), []);
  assert.deepEqual(eolJudge(eolData({ ranges: [{ type: 'PHP_BRANCH', branch: '8.1', fixed: '8.1.10' }] })), []);
});
