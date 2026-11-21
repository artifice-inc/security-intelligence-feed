import test from 'node:test';
import assert from 'node:assert/strict';
import { matchRuntimes } from '../src/match/runtime-match.mjs';
import { runtimeErrors } from '../src/match/python-runtime.mjs';
import { detectProject } from '../src/match/match-project.mjs';
import { requiredSources, decideScanStatus } from '../src/match/scan-status.mjs';
import { buildSummary, buildLocalScan, buildCentralIssues, pythonSourcesFresh } from '../src/local/check-summary.mjs';
import { detectStack, dockerfilePythonTag } from '../src/inventory/detect-stack.mjs';
import { validate } from '../src/lib/schema.mjs';
import { makeTree } from './helpers/tree.mjs';
import { inventoryOf, stubExec } from './helpers/match-fixtures.mjs';

const SYNCED = '2026-11-19T03:00:00Z';
const v = (version, date) => ({ version, date });
const pyData = (overrides = {}) => ({
  runtime: 'python', updated_at: SYNCED, psf_synced_at: SYNCED, pending: [],
  branches: [
    { branch: '3.12', state: 'maintained', security_support_end: '2028-10-31', is_eol: false, latest_version: '3.12.17', versions: [v('3.12.7', '2024-10-01'), v('3.12.13', '2026-02-03'), v('3.12.16', '2026-10-25'), v('3.12.17', '2026-11-16')] },
    { branch: '3.8', state: 'eol', security_support_end: '2024-10-07', is_eol: true, latest_version: '3.8.20', versions: [v('3.8.20', '2024-09-06')] },
    { branch: '2.7', state: 'eol', security_support_end: '2020-01-01', is_eol: true, latest_version: '2.7.18', versions: [v('2.7.18', '2020-04-20')] },
  ],
  advisories: [
    { key: 'CVE-2026-2297', aliases: ['CVE-2026-2297', 'PSF-2026-9'], ranges: [{ type: 'PY_VERSIONS', affected: ['3.12.0', '3.12.7', '3.12.13', '3.12.17', '3.13.0'], fixed: ['3.12.18', '3.13.13'] }], fixed_versions: ['3.12.18', '3.13.13'], source_urls: ['https://osv.dev/vulnerability/PSF-2026-9'], published_at: '2026-03-01T00:00:00Z' },
  ],
  ...overrides,
});
const withPython = (python, extra = {}) => inventoryOf({
  files: [], lockfiles: [],
  runtimes: { php: { version: null, constraint: null, source: null }, node: { version: null, constraint: null, source: null }, python }, ...extra,
});
const UNKNOWN_ITEM = { advisory_key: 'RUNTIME-UNKNOWN-python', priority: 'P3', locations: [] };
const exact = (version) => ({ version, constraint: null, source: '.python-version' });
const match = (version, data = pyData(), extra = {}) => matchRuntimes({ inventory: withPython(exact(version)), runtimeData: { python: data }, conditions: {}, ...extra });
const keys = (detections) => detections.map((d) => d.advisory_key).sort();
const errorsOf = (python, data = pyData()) => runtimeErrors({ inventory: withPython(python), runtimeData: { python: data }, graceDays: 7 });

test('python: 影響タグにある版は affected で、修正版は同じブランチのものだけ', () => {
  const found = match('3.12.7');
  assert.deepEqual(keys(found), ['CVE-2026-2297']);
  assert.deepEqual([found[0].judgement, found[0].fixed_versions, found[0].locations[0].package], ['affected', ['3.12.18'], 'python']);
  assert.deepEqual(errorsOf(exact('3.12.7')), []);
});

test('python: 影響タグにない実在の版（リリースから7日以上）は検出なし・エラーなし', () => {
  assert.deepEqual(match('3.12.16'), []);
  assert.deepEqual(errorsOf(exact('3.12.16')), []);
});

test('python: 実在しない版（データより新しい版・最新版以下でも一覧にない版）は RUNTIME-UNKNOWN-python が1件だけで、アドバイザリの検出は0件。エラーは inventory が1件', () => {
  for (const version of ['3.12.99', '3.12.5', '3.15.0']) {
    const found = match(version);
    assert.deepEqual(keys(found), ['RUNTIME-UNKNOWN-python'], version);
    assert.match(found[0].evidence, new RegExp(`版 ${version} は python.org の正式版の一覧にありません`));
    const errors = errorsOf(exact(version));
    assert.deepEqual(errors.map((e) => e.kind), ['inventory'], version);
    assert.match(errors[0].message, new RegExp(`版 ${version} を python.org の正式版の一覧で確かめられません`));
  }
  // versions がない古いデータ・ブランチがないデータも同じ
  const old = pyData({ branches: [{ branch: '3.12', state: 'maintained', security_support_end: null, is_eol: false, latest_version: null }] });
  assert.deepEqual(keys(match('3.12.7', old)), ['RUNTIME-UNKNOWN-python']);
  assert.deepEqual(keys(match('3.12.7', null)), ['RUNTIME-UNKNOWN-python']);
});

test('python: 版が確定しない（制約だけ・手がかりなし）は RUNTIME-UNKNOWN-python と、版が確定しないエラー（inventory）', () => {
  const constraint = { version: null, constraint: '3.12', source: 'Dockerfile' };
  const found = matchRuntimes({ inventory: withPython(constraint), runtimeData: { python: pyData() }, conditions: {} });
  assert.deepEqual(keys(found), ['RUNTIME-UNKNOWN-python']);
  assert.deepEqual(found[0].locations[0].installed_version, '3.12');
  const errors = errorsOf(constraint);
  assert.deepEqual(errors.map((e) => [e.kind, e.target]), [['inventory', 'Dockerfile']]);
  assert.match(errors[0].message, /CPython の版が確定しません/);
  assert.equal(errorsOf({ version: null, constraint: null, source: null })[0].target, 'python');
});

test('python: 猶予期間中の版（リリース3日後）は、影響タグにあれば affected、なければ検出せず、エラー（source）が1件', () => {
  const found = match('3.12.17');
  assert.deepEqual(keys(found), ['CVE-2026-2297'], '影響タグにある CVE は affected で出る');
  const other = pyData({ advisories: [{ ...pyData().advisories[0], ranges: [{ type: 'PY_VERSIONS', affected: ['3.12.7'], fixed: [] }] }] });
  assert.deepEqual(match('3.12.17', other), [], '影響タグにない CVE は出ない');
  const errors = errorsOf(exact('3.12.17'), other);
  assert.deepEqual(errors.map((e) => [e.kind, e.target]), [['source', 'python-psf']]);
  assert.match(errors[0].message, /版 3\.12\.17 はリリースから 7 日以内で、OSV の補完を確認できません（2026-11-23 以降に判定します）/);
});

test('python: 猶予明けの判定は照合の now ではなく psf_synced_at（ローカルで中央の古いデータを使っても猶予明けにならない）', () => {
  // 3.12.17 のリリースは 2026-11-16。6日目（11-22）に取り込んだデータは、8日目にローカルで使っても猶予中
  const sixth = pyData({ psf_synced_at: '2026-11-22T00:00:00Z' });
  assert.equal(errorsOf(exact('3.12.17'), sixth).length, 1);
  assert.deepEqual(errorsOf(exact('3.12.17'), pyData({ psf_synced_at: '2026-11-23T00:00:00Z' })), [], '7日目以降に取り込んだデータでは猶予明け');
  assert.equal(errorsOf(exact('3.12.17'), pyData({ psf_synced_at: null })).length, 1, 'null は猶予中と同じ');
});

test('python: データがない・pending がある回は、検出は出したうえでエラー（source）。pending は先頭5件まで', () => {
  const pending = Array.from({ length: 7 }, (_, i) => ({ id: `PSF-2026-${i + 1}`, reason: 'osv_missing', since: SYNCED }));
  const data = pyData({ pending });
  assert.deepEqual(keys(match('3.12.7', data)), ['CVE-2026-2297'], '取得済みの検出は出す');
  const [error] = errorsOf(exact('3.12.7'), data);
  assert.equal(error.target, 'python-psf');
  assert.match(error.message, /7件あります（PSF-2026-1、PSF-2026-2、PSF-2026-3、PSF-2026-4、PSF-2026-5 ほか）/);
  assert.deepEqual(errorsOf(exact('3.12.7'), null).map((e) => e.message), ['版 3.12.7 を python.org の正式版の一覧で確かめられません（.security/stack.yml の runtimes.python を確認してください）', 'CPython の脆弱性データがありません']);
});

test('python: python の手がかりがない案件（inventory.runtimes に python がない）は、検出もエラーも出ない', () => {
  const inventory = inventoryOf();
  assert.ok(!('python' in inventory.runtimes));
  assert.deepEqual(runtimeErrors({ inventory, runtimeData: {} }), []);
  assert.ok(!matchRuntimes({ inventory, runtimeData: { python: pyData() } }).some((d) => /python/i.test(d.advisory_key)));
});

test('python: EOL のブランチ（3.8.20）は EOL-python-3.8 が出る。EOL 後に公開され 3.8 のタグがない記録は needs_review、EOL 前の公開は出ない', () => {
  const advisory = (key, published, affected) => ({ key, aliases: [key], ranges: [{ type: 'PY_VERSIONS', affected, fixed: [] }], fixed_versions: [], source_urls: [], published_at: published });
  const data = pyData({ advisories: [advisory('PSF-2025-4', '2025-02-01T00:00:00Z', ['3.9.0', '3.12.1']), advisory('PSF-2023-9', '2023-02-01T00:00:00Z', ['3.9.0']), advisory('PSF-2025-5', '2025-03-01T00:00:00Z', ['3.8.20'])] });
  const found = match('3.8.20', data);
  assert.deepEqual(keys(found), ['EOL-python-3.8', 'PSF-2025-4', 'PSF-2025-5']);
  const byKey = Object.fromEntries(found.map((d) => [d.advisory_key, d.judgement]));
  assert.deepEqual(byKey, { 'EOL-python-3.8': 'affected', 'PSF-2025-4': 'needs_review', 'PSF-2025-5': 'affected' });
  assert.match(found.find((d) => d.advisory_key === 'PSF-2025-4').evidence, /EOL のブランチ 3\.8/);
});

test('python: review_below より小さい版は needs_review。manual_review（UNPARSED）は全版で needs_review。範囲に該当しない版は検出なし', () => {
  const data = pyData({ advisories: [
    { key: 'PSF-2014-6', aliases: ['PSF-2014-6'], ranges: [{ type: 'PY_VERSIONS', affected: [], fixed: [], review_below: '3.0.0' }], fixed_versions: [], source_urls: [], published_at: '2014-01-01T00:00:00Z' },
    { key: 'PSF-2023-4', aliases: ['PSF-2023-4'], ranges: [{ type: 'UNPARSED', raw: '人が確認する' }], fixed_versions: [], source_urls: [], published_at: '2023-01-01T00:00:00Z' },
    { key: 'PSF-2023-3', aliases: ['PSF-2023-3'], ranges: [{ type: 'PY_VERSIONS', affected: [], fixed: [] }], fixed_versions: [], source_urls: [], published_at: '2023-01-01T00:00:00Z' },
  ] });
  assert.deepEqual(keys(match('2.7.18', data)), ['EOL-python-2.7', 'PSF-2014-6', 'PSF-2023-3', 'PSF-2023-4'], 'PSF-2023-3 は EOL 後の公開でそのブランチの範囲がないため、EOL のブランチでは要確認');
  assert.deepEqual(keys(match('3.12.7', data)), ['PSF-2023-4']);
});

test('node: EOL ブランチで、EOL 後に公開されたそのブランチの範囲がないアドバイザリは今までどおり検出なし（needs_review にならない）。EOL-node は出る', () => {
  const runtimeData = { nodejs: { branches: [{ branch: '16', state: 'eol', security_support_end: '2023-09-11', is_eol: true, latest_version: '16.20.2' }], advisories: [{ key: 'CVE-N', aliases: ['CVE-N'], ranges: [{ type: 'NODE_SEMVER', vulnerable: '>=18.0.0 <18.5.0', patched: '>=18.5.0', fixed_versions: ['18.5.0'] }], fixed_versions: ['18.5.0'], source_urls: [], published_at: '2024-01-01T00:00:00Z' }] } };
  const inventory = inventoryOf({ runtimes: { php: { version: null, constraint: null, source: null }, node: { version: '16.20.2', constraint: null, source: '.nvmrc' } } });
  assert.deepEqual(keys(matchRuntimes({ inventory, runtimeData, conditions: {} })), ['EOL-node-16']);
});

// ---- 集計 ---------------------------------------------------------------------------------

const fresh = (at = SYNCED) => ({ sources: Object.fromEntries(['python-psf', 'python-releases', 'endoflife-python'].map((n) => [n, { last_success_at: at, last_error: null }])) });
const NOW = new Date('2026-11-19T06:00:00Z');
const rowOf = (python, { data = pyData(), health = fresh(), items = [] } = {}) => buildSummary({
  inventory: withPython(python), osvAvailable: {}, checks: {}, scanErrors: [], items, runtimeData: { python: data }, health, now: NOW,
}).rows.find((r) => r.target === 'python');

test('buildSummary: python の行は ok / unknown / unavailable を条件の順で決める', () => {
  assert.equal(rowOf(exact('3.12.7')).state, 'ok');
  assert.equal(rowOf({ version: null, constraint: '3.12', source: 'Dockerfile' }, { items: [UNKNOWN_ITEM] }).state, 'unknown');
  assert.equal(rowOf(exact('3.12.99'), { items: [UNKNOWN_ITEM] }).state, 'unknown');
  assert.equal(rowOf(exact('3.12.17')).state, 'unknown', '猶予期間中');
  assert.equal(rowOf(exact('3.12.7'), { data: null }).state, 'unavailable');
  assert.equal(rowOf(exact('3.12.7'), { data: pyData({ pending: [{ id: 'PSF-1', reason: 'osv_missing', since: SYNCED }] }) }).state, 'unavailable');
  assert.equal(rowOf({ version: null, constraint: null, source: null }).state, 'unknown');
});

test('buildSummary: Python 用の情報源が新しくなければ unavailable（取得失敗・37時間前の成功・health なし）。3つとも12時間前なら ok', () => {
  const thresholds = { stale_source_hours: 36 };
  const failing = fresh(); failing.sources['python-releases'].last_error = { message: 'x' };
  assert.equal(rowOf(exact('3.12.7'), { health: failing }).state, 'unavailable');
  const old = fresh(); old.sources['endoflife-python'].last_success_at = '2026-11-17T17:00:00Z';
  assert.equal(rowOf(exact('3.12.7'), { health: old }).state, 'unavailable');
  assert.equal(rowOf(exact('3.12.7'), { health: null }).state, 'unavailable');
  assert.equal(rowOf(exact('3.12.7'), { health: fresh('2026-11-18T18:00:00Z') }).state, 'ok');
  assert.equal(pythonSourcesFresh({ health: { sources: {} }, now: NOW, thresholds }), false);
  assert.equal(pythonSourcesFresh({ health: fresh(), now: NOW, thresholds }), true);
});

test('ローカル: python の行が unknown・unavailable のとき local_scan.complete は false で、resolved_locally は null（前回の Issue をクローズ候補にしない）', () => {
  for (const state of ['unknown', 'unavailable']) {
    const summary = { rows: [{ target: 'python', kind: 'runtime', state }], total: {} };
    const localScan = buildLocalScan({ summary, scanErrors: [], pullOk: true, localOsvDb: {}, central: { provenance: {} }, inventory: withPython(exact('3.12.7')) });
    assert.equal(localScan.complete, false);
    const issues = [{ issue_number: 1, project: 'demo', aliases: ['CVE-2026-2297'], state: 'open', labels: ['P2'] }];
    assert.equal(buildCentralIssues({ issuesFile: issues, projectName: 'demo', localScan, aliasSets: [] }).resolved_locally, null);
  }
});

test('scan-status: python 案件は python-psf・python-releases・endoflife-python が必須の情報源。それ以外の案件は変わらない', () => {
  assert.deepEqual(requiredSources(withPython(exact('3.12.7'))), ['kev', 'epss', 'endoflife', 'python-psf', 'python-releases', 'endoflife-python']);
  assert.deepEqual(requiredSources(inventoryOf()), ['kev', 'epss', 'endoflife', 'node-core', 'node-dist']);
  const base = { kev: { ok: true }, epss: { ok: true }, endoflife: { ok: true }, 'python-psf': { ok: true }, 'python-releases': { ok: true } };
  const status = decideScanStatus({ inventory: withPython(exact('3.12.7')), inventoryStatus: 'fresh', sourceResults: { ...base, 'endoflife-python': { ok: false } }, osvDb: {}, packagistFullSyncAt: null, scanErrors: [] });
  assert.equal(status.scan_status, 'partial');
  const ok = decideScanStatus({ inventory: inventoryOf(), inventoryStatus: 'fresh', sourceResults: { ...base, 'node-core': { ok: true }, 'node-dist': { ok: true }, 'endoflife-python': { ok: false }, 'python-psf': { ok: false } }, osvDb: { npm: true }, packagistFullSyncAt: null, scanErrors: [] });
  assert.equal(ok.scan_status, 'complete', 'Python のない案件は Python 用の情報源の失敗で partial にならない');
});

test('detectProject: python の版が確定しない案件は、取得済みの検出を残したまま scan_errors に python のエラーが入る', async () => {
  const inventory = withPython({ version: '3.12.7', constraint: null, source: '.python-version' });
  const result = await detectProject({ inventory, workdir: null, exec: stubExec(0, '{}'), scannerPath: 'x', dbDir: '/db', osvAvailable: {}, runtimeData: { python: pyData({ pending: [{ id: 'PSF-1', reason: 'osv_missing', since: SYNCED }] }) }, packagistAdvisories: null });
  assert.ok(result.detections.some((d) => d.advisory_key === 'CVE-2026-2297'));
  assert.deepEqual(result.errors.map((e) => e.target), ['python-psf']);
});

// ---- 版の検出 --------------------------------------------------------------------------------

const detectPython = (files) => detectStack(makeTree(files)).runtimes.python;

test('detectStack: .python-version・stack.yml・Dockerfile の順で版を決める。3.12 や pypy3.10 は制約', () => {
  assert.deepEqual(detectPython({ '.python-version': '3.12.7\n', 'Dockerfile': 'FROM python:3.11.1\n' }), { version: '3.12.7', constraint: null, source: '.python-version' });
  assert.deepEqual(detectPython({ '.python-version': '3.12\n' }), { version: null, constraint: '3.12', source: '.python-version' });
  assert.deepEqual(detectPython({ '.python-version': 'pypy3.10\n' }), { version: null, constraint: 'pypy3.10', source: '.python-version' });
  assert.equal(detectPython({ '.python-version': '3.12.7\n', '.security/stack.yml': 'runtimes:\n  python: "3.13.1"\n' }).version, '3.13.1');
  assert.deepEqual(detectPython({ 'poetry.lock': 'x' }), { version: null, constraint: null, source: null });
  assert.equal(detectPython({ 'pyproject.toml': '[project]\n' }).version, null);
  assert.equal(detectPython({ 'Pipfile': 'x', 'Dockerfile': 'FROM python:3.12.4-slim\n' }).version, '3.12.4');
});

test('detectStack: Python の手がかりがない案件には python のキーを作らない（inventory のキーが変わらない）', () => {
  for (const files of [{ 'package-lock.json': '{}', '.nvmrc': '22.11.0' }, { 'composer.lock': '{}', Dockerfile: 'FROM php:8.2.30\n' }, { Dockerfile: 'FROM node:22\n' }, { 'README.md': 'x' }]) {
    assert.deepEqual(Object.keys(detectStack(makeTree(files)).runtimes), ['node', 'php'], JSON.stringify(files));
  }
});

test('stack.yml: runtimes.python を書けて、スキーマを通る（stack.yml 全体が無視されない）', () => {
  assert.equal(validate('stack', { runtimes: { python: '3.12.7' } }).ok, true);
  assert.equal(validate('stack', { runtimes: { ruby: '3' } }).ok, false, 'additionalProperties は残す');
  assert.equal(validate('inventory', inventoryOf({ runtimes: { php: { version: null, constraint: null, source: null }, node: { version: null, constraint: null, source: null }, python: exact('3.12.7') } })).ok, true);
});

test('dockerfilePythonTag: 最終ステージだけを見る。正式版の完全一致だけが版で、rc・b・3.12-slim は制約', () => {
  const tag = (files) => dockerfilePythonTag(makeTree(files));
  assert.equal(tag({ Dockerfile: 'FROM python:3.12.7 AS build\nRUN x\nFROM gcr.io/distroless/base\nCOPY --from=build /a /a\n' }), null, '最終ステージが python でなければ手がかりにしない');
  assert.deepEqual(tag({ Dockerfile: 'FROM node:22 AS assets\nFROM python:3.12.7-slim\n' }), { text: '3.12.7', source: 'Dockerfile' });
  assert.deepEqual(tag({ Dockerfile: 'FROM python:3.12-slim\n' }), { text: '3.12', source: 'Dockerfile', constraintOnly: true });
  assert.equal(tag({ Dockerfile: 'FROM python:3.14.0rc1-slim\n' }).constraintOnly, true);
  assert.equal(tag({ Dockerfile: 'FROM python:3.14.0b2-slim\n' }).text, '3.14.0b2-slim');
  assert.equal(tag({ Dockerfile: 'FROM --platform=linux/amd64 docker.io/library/python:3.12.7\n' }).text, '3.12.7');
  assert.equal(tag({ Dockerfile: 'ARG V=3.12\nFROM python:$V\n' }), null, '$ を含むタグは無視する');
  const conflict = tag({ Dockerfile: 'FROM python:3.12.7\n', 'Dockerfile.dev': 'FROM python:3.13.1\n' });
  assert.deepEqual([conflict.text, conflict.constraintOnly], ['複数の Dockerfile で版が異なります（3.12.7、3.13.1）', true]);
  assert.equal(tag({ Dockerfile: 'FROM python:3.12.7\n', 'Dockerfile.dev': 'FROM python:3.12.7-slim\n' }).text, '3.12.7', '食い違わなければ版');
  // 版が確定しなければ RUNTIME-UNKNOWN-python になる（コニシ案件の形）
  const runtime = detectPython({ Dockerfile: 'FROM python:3.12-slim\n' });
  assert.deepEqual(runtime, { version: null, constraint: '3.12', source: 'Dockerfile' });
});

test('dockerfileTag（node・php）の結果は変わらない', () => {
  const runtimes = detectStack(makeTree({ Dockerfile: 'FROM node:22.11.0-alpine\nFROM php:8.2.30-fpm\n' })).runtimes;
  assert.equal(runtimes.node.version, '22.11.0');
  assert.equal(runtimes.php.version, '8.2.30');
  assert.ok(!('python' in runtimes));
});
