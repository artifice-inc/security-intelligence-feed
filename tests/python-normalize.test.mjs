import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fromPythonPsf, fromOsv, fromNodeCore } from '../src/normalize/sources.mjs';
import { mergeAdvisories } from '../src/normalize/advisories.mjs';
import { buildPythonRuntime, buildNodeRuntime, pythonRuntimeAdvisories, branchOf } from '../src/normalize/runtimes.mjs';
import { normalizeAll, osvSourceEcosystem } from '../src/publish/stage-collect.mjs';
import { collectProblems } from '../src/publish/health.mjs';
import { zipPathOf } from '../src/collect/osv-db.mjs';
import { assertValid } from '../src/lib/schema.mjs';
import { psfRecord, TAGS_3_12, releaseRecords, eolPython, NO_IMPACT, T } from './helpers/python-fixtures.mjs';
import { osvRecord } from './helpers/osv-records.mjs';

const convert = (raw, extra = {}) => fromPythonPsf(raw, { now: T, releases: releaseRecords, noImpact: NO_IMPACT, graceDays: 7, ...extra });
const NOW = '2026-11-19T03:00:00Z';

test('fromPythonPsf: 影響タグから PY_VERSIONS を作る。ids・title・severity・category を設定する', () => {
  const { record, pendingReason } = convert(psfRecord('PSF-2026-9', TAGS_3_12));
  assert.equal(pendingReason, null);
  assert.deepEqual(record.ids, ['PSF-2026-9', 'CVE-2026-2297', 'BIT-python-2026-2297']);
  assert.equal(record.url, 'https://osv.dev/vulnerability/PSF-2026-9');
  assert.equal(record.title, 'Example CPython bug');
  assert.deepEqual([record.category, record.ecosystem, record.verification_status, record.withdrawn_at], ['runtime', 'python', 'source_structured', null]);
  assert.deepEqual(record.severity, { level: null, source: 'python-psf', cvss_v3: null, cvss_v4: null, rank: 2 });
  assert.deepEqual(record.affected[0].package, { ecosystem: 'python', name: 'python' });
  assert.deepEqual(record.affected[0].from_sources, ['python-psf:PSF-2026-9']);
  assert.deepEqual(record.affected[0].ranges, [{ type: 'PY_VERSIONS', affected: ['3.12.0', '3.12.1', '3.12.7', '3.12.13', '3.13.0'], fixed: ['3.12.14'] }]);
  assert.equal(convert(psfRecord('X', TAGS_3_12, { summary: '' })).record.title, 'Example details');
  assert.equal(convert(psfRecord('X', TAGS_3_12, { summary: '', details: '' })).record.title, 'X');
});

test('fromPythonPsf: 猶予期間中の版は修正版にしない。8日後に入る', () => {
  const early = convert(psfRecord('X', TAGS_3_12), { now: '2026-11-04T00:00:00Z' }).record.affected[0].ranges[0];
  assert.deepEqual(early.fixed, []);
  assert.deepEqual(convert(psfRecord('X', TAGS_3_12), { now: '2026-11-09T00:00:00Z' }).record.affected[0].ranges[0].fixed, ['3.12.14']);
});

test('fromPythonPsf: 影響タグが空のとき、一覧の no_impact は pending に入らず、一覧にない記録は UNPARSED で no_versions', () => {
  const all = convert(psfRecord('PSF-ALPHA', ['v3.12.0b1', 'v3.12.0b3']));
  assert.equal(all.pendingReason, null);
  assert.deepEqual(all.record.affected[0].ranges, [{ type: 'PY_VERSIONS', affected: [], fixed: [] }]);
  assert.equal(all.record.verification_status, 'source_structured');
  const min = convert(psfRecord('PSF-OLD-1', []));
  assert.deepEqual(min.record.affected[0].ranges, [{ type: 'PY_VERSIONS', affected: [], fixed: [], review_below: '3.0.0' }]);
  assert.equal(min.pendingReason, null);
  const manual = convert(psfRecord('PSF-MANUAL', []));
  assert.deepEqual([manual.record.affected[0].ranges[0].type, manual.record.verification_status, manual.pendingReason], ['UNPARSED', 'needs_review', null]);
  const unknown = convert(psfRecord('PSF-NEW-1', []));
  assert.deepEqual([unknown.record.affected[0].ranges[0].type, unknown.record.verification_status, unknown.pendingReason], ['UNPARSED', 'needs_review', 'no_versions']);
  assert.match(unknown.record.affected[0].ranges[0].raw, /補完待ち/);
});

test('fromPythonPsf: 取り下げは影響タグの判定より先に処理し、pending に入れない（affected が空でも）', () => {
  const { record, pendingReason } = convert(psfRecord('PSF-NEW-2', [], { withdrawn: '2026-11-01T00:00:00Z', affected: [] }));
  assert.equal(pendingReason, null);
  assert.equal(record.withdrawn_at, '2026-11-01T00:00:00Z');
  // 撤回後（withdrawn がなくなった）は通常の判定に戻る
  assert.equal(convert(psfRecord('PSF-NEW-2', [], { affected: [] })).pendingReason, 'no_versions');
  assert.equal(convert(psfRecord('PSF-NEW-2', TAGS_3_12)).pendingReason, null);
});

// ---- normalizeAll（stage-collect）----------------------------------------------------------

function makeDb(records = {}) {
  const dir = mkdtempSync(path.join(tmpdir(), 'si-pydb-'));
  for (const [eco, list] of Object.entries(records)) {
    const src = path.join(dir, `src-${eco}`);
    mkdirSync(src, { recursive: true });
    for (const r of list) writeFileSync(path.join(src, `${r.id}.json`), JSON.stringify(r));
    mkdirSync(path.dirname(zipPathOf(dir, eco)), { recursive: true });
    execFileSync('zip', ['-q', '-j', zipPathOf(dir, eco), ...list.map((r) => path.join(src, `${r.id}.json`))]);
  }
  return dir;
}
const okPsf = (records, missing = []) => ({ ok: true, records, missing });
const emptyData = (overrides = {}) => ({ advisories: [], runtimes: { php: null, nodejs: null, python: null }, jpAlerts: null, packagist: null, amazonLinuxKernel: null, ...overrides });
const FAIL = { ok: false, records: [], error: { kind: 'network', message: 'x', http_status: null } };
const run = (results, data = emptyData(), extra = {}) => normalizeAll({
  results: { 'python-psf': okPsf([]), 'python-releases': { ok: true, records: releaseRecords }, 'endoflife-python': { ok: true, records: eolPython }, ...results },
  packagistPlan: { full: true, updatedSince: 0 }, data, osvDbDir: makeDb(), osvFetchedThisRun: { npm: true, Packagist: true, PyPI: true }, now: NOW, ...extra,
});
const withData = (norm, previousRuntime) => emptyData({ advisories: [...norm.advisories.values()], runtimes: { php: null, nodejs: null, python: previousRuntime ?? norm.runtimes.python } });

test('正規化: python.json を作る（branches.versions・advisories・pending・psf_synced_at）。スキーマを通る', async () => {
  const norm = await run({ 'python-psf': okPsf([psfRecord('PSF-2026-9', TAGS_3_12), psfRecord('PSF-NEW-1', [], { aliases: [] })], ['PSF-2026-404']) });
  const python = norm.runtimes.python;
  assertValid('runtimes', python);
  assert.equal(python.runtime, 'python');
  assert.equal(python.psf_synced_at, NOW);
  assert.deepEqual(python.pending, [{ id: 'PSF-2026-404', reason: 'osv_missing', since: NOW }, { id: 'PSF-NEW-1', reason: 'no_versions', since: NOW }].sort((a, b) => (a.id < b.id ? -1 : 1)));
  const b312 = python.branches.find((b) => b.branch === '3.12');
  assert.deepEqual([b312.state, b312.latest_version, b312.security_support_end], ['maintained', '3.12.14', '2028-10-31']);
  assert.deepEqual(b312.versions.at(-1), { version: '3.12.14', date: '2026-11-01' });
  assert.equal(python.branches.find((b) => b.branch === '3.8').state, 'eol');
  assert.deepEqual(python.advisories.map((a) => a.key), ['CVE-2026-2297', 'PSF-NEW-1']);
  const cve = python.advisories[0];
  assert.deepEqual(cve.ranges[0].affected.slice(0, 2), ['3.12.0', '3.12.1']);
  assert.deepEqual(cve.fixed_versions, ['3.12.14']);
  assert.ok(cve.aliases.includes('PSF-2026-9'));
});

test('正規化: pending の since は最初の値を保ち、解消したら外れる。冪等（2回目は何も変わらない）', async () => {
  const first = await run({ 'python-psf': okPsf([], ['PSF-2026-404']) });
  const later = await run({ 'python-psf': okPsf([], ['PSF-2026-404']) }, withData(first), { now: '2026-11-20T03:00:00Z' });
  assert.equal(later.runtimes.python.pending[0].since, NOW);
  assert.equal(later.runtimes.python.psf_synced_at, '2026-11-20T03:00:00Z');
  const resolved = await run({ 'python-psf': okPsf([psfRecord('PSF-2026-404', TAGS_3_12)]) }, withData(later), { now: '2026-11-21T03:00:00Z' });
  assert.deepEqual(resolved.runtimes.python.pending, []);
  // 同じ入力で2回実行すると、2回目は advisories・updated_at・history が変わらない
  const once = await run({ 'python-psf': okPsf([psfRecord('PSF-2026-9', TAGS_3_12)]) });
  const twice = await run({ 'python-psf': okPsf([psfRecord('PSF-2026-9', TAGS_3_12)]) }, withData(once));
  assert.deepEqual(twice.runtimes.python, once.runtimes.python);
  assert.deepEqual([...twice.advisories.values()], [...once.advisories.values()], 'アドバイザリは1バイトも変わらない');
});

test('正規化: python-releases か python-psf が失敗した回は、前回の advisories・pending・psf_synced_at が1バイトも変わらない', async () => {
  const good = await run({ 'python-psf': okPsf([psfRecord('PSF-2026-9', TAGS_3_12)], ['PSF-2026-404']) });
  const previous = withData(good);
  for (const failing of [{ 'python-releases': FAIL }, { 'python-psf': FAIL }, { 'python-psf': FAIL, 'python-releases': FAIL }]) {
    const norm = await run(failing, previous, { now: '2026-11-25T03:00:00Z' });
    assert.deepEqual([...norm.advisories.values()], [...good.advisories.values()]);
    assert.equal(JSON.stringify({ ...norm.runtimes.python, branches: 0 }), JSON.stringify({ ...good.runtimes.python, branches: 0 }));
  }
  const noEol = await run({ 'endoflife-python': FAIL }, previous, { now: '2026-11-25T03:00:00Z' });
  assert.deepEqual(noEol.runtimes.python.branches, good.runtimes.python.branches, 'EOL が取れない回は前回の branches を使う');
  assert.equal(noEol.runtimes.python.psf_synced_at, '2026-11-25T03:00:00Z');
});

test('正規化: 初期の確認済みの一覧では PSF-2023-4 は UNPARSED だが pending に入らず、pending が空になる', async () => {
  const six = ['PSF-2014-6', 'PSF-2017-6', 'PSF-2018-2', 'PSF-2023-3', 'PSF-2023-4', 'PSF-2023-7'].map((id) => psfRecord(id, id === 'PSF-2023-7' ? ['v3.12.0b1'] : [], { aliases: [] }));
  const norm = await run({ 'python-psf': okPsf(six) });
  assert.deepEqual(norm.runtimes.python.pending, []);
  const entry = norm.runtimes.python.advisories.find((a) => a.key === 'PSF-2023-4');
  assert.equal(entry.ranges[0].type, 'UNPARSED');
  assert.equal(norm.advisories.get('PSF-2023-4').verification_status, 'needs_review');
});

test('正規化: 取り下げられた記録は withdrawn になり python.json から外れる。撤回で active に戻る', async () => {
  const active = await run({ 'python-psf': okPsf([psfRecord('PSF-2026-9', TAGS_3_12)]) });
  const withdrawn = await run({ 'python-psf': okPsf([psfRecord('PSF-2026-9', [], { withdrawn: '2026-11-10T00:00:00Z', affected: [] })]) }, withData(active), { now: '2026-11-20T03:00:00Z' });
  assert.equal(withdrawn.advisories.get('CVE-2026-2297').status, 'withdrawn');
  assert.deepEqual(withdrawn.runtimes.python.advisories, []);
  assert.deepEqual(withdrawn.runtimes.python.pending, [], '取り下げは pending に入らない');
  const restored = await run({ 'python-psf': okPsf([psfRecord('PSF-2026-9', TAGS_3_12)]) }, withData(withdrawn), { now: '2026-11-21T03:00:00Z' });
  assert.equal(restored.advisories.get('CVE-2026-2297').status, 'active');
  assert.equal(restored.runtimes.python.advisories.length, 1);
});

test('正規化: 新しいリリースで影響タグと修正版が増えると、history に affected の変化が1件記録される', async () => {
  const first = await run({ 'python-psf': okPsf([psfRecord('PSF-2026-9', TAGS_3_12)]) });
  const grown = await run({ 'python-psf': okPsf([psfRecord('PSF-2026-9', [...TAGS_3_12, 'v3.12.14'])]) }, withData(first), { now: '2026-11-25T03:00:00Z' });
  assert.deepEqual(grown.advisories.get('CVE-2026-2297').history.map((h) => h.changes), [['affected']]);
});

// ---- 同じ CVE の統合と OSV の定期更新 ------------------------------------------------------

const ghsaPyPI = (overrides = {}) => osvRecord({ id: 'GHSA-pypi-aaaa-bbbb', aliases: ['CVE-2026-2297'], affected: [{ package: { ecosystem: 'PyPI', name: 'pkg' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '2.0.0' }] }] }], ...overrides });

test('同じ CVE の PyPI のアドバイザリが先にあっても、PSF を統合すると affected に python の要素が加わる。python.json は python の要素の範囲だけ', async () => {
  const stored = mergeAdvisories({ previous: [], records: [fromOsv(ghsaPyPI(), { now: NOW, dbEcosystem: 'PyPI' })], now: NOW });
  const norm = await run({ 'python-psf': okPsf([psfRecord('PSF-2026-9', TAGS_3_12)]) }, emptyData({ advisories: [...stored.values()] }));
  const merged = norm.advisories.get('CVE-2026-2297') ?? norm.advisories.get('GHSA-pypi-aaaa-bbbb');
  assert.deepEqual([merged.category, merged.ecosystem], ['dependency', 'PyPI']);
  assert.deepEqual(merged.affected.map((a) => a.package.ecosystem).sort(), ['PyPI', 'python']);
  const [entry] = norm.runtimes.python.advisories;
  assert.deepEqual(entry.ranges.map((r) => r.type), ['PY_VERSIONS'], 'PyPI の ECOSYSTEM の範囲を混ぜない');
  assert.deepEqual(entry.fixed_versions, ['3.12.14']);
  // 純粋関数の単体
  assert.equal(pythonRuntimeAdvisories([merged]).length, 1);
  assert.equal(pythonRuntimeAdvisories([{ ...merged, superseded_by: 'X' }, { ...merged, status: 'withdrawn' }]).length, 0);
  assert.equal(pythonRuntimeAdvisories([stored.values().next().value]).length, 0, 'PyPI だけのものは拾わない');
});

test('情報源ごとのエコシステム: 保存され、affected のない取り下げでも既知の値を unknown で上書きしない', () => {
  const withdrawnRaw = osvRecord({ id: 'GHSA-pypi-aaaa-bbbb', aliases: ['CVE-2026-2297'], withdrawn: '2026-11-01T00:00:00Z', affected: undefined });
  assert.equal(fromOsv(withdrawnRaw, { now: NOW }).ecosystem, 'unknown');
  const first = mergeAdvisories({ previous: [], records: [fromOsv(ghsaPyPI(), { now: NOW, dbEcosystem: 'PyPI' })], now: NOW });
  const advisory = first.values().next().value;
  assert.equal(advisory.sources[0].ecosystem, 'PyPI');
  const next = mergeAdvisories({ previous: [advisory], records: [fromOsv(withdrawnRaw, { now: NOW, dbEcosystem: 'PyPI' })], now: '2026-11-20T00:00:00Z' }).values().next().value;
  assert.equal(next.sources[0].ecosystem, 'PyPI');
  assert.equal(next.affected.length, 0, '取り下げで影響範囲は消える');
  assert.equal(osvSourceEcosystem(next, next.sources[0]), 'PyPI');
  // スキャナ由来で db_ecosystem が取れない（フェイクの）記録を渡しても、保存済みの ecosystem は消えない
  const again = mergeAdvisories({ previous: [next], records: [fromOsv(ghsaPyPI(), { now: NOW })], now: '2026-11-21T00:00:00Z' }).values().next().value;
  assert.equal(again.sources[0].ecosystem, 'PyPI');
  // ECOSYSTEMS にない値は保存しない
  const odd = mergeAdvisories({ previous: [], records: [fromOsv(ghsaPyPI(), { now: NOW, dbEcosystem: 'Go' })], now: NOW }).values().next().value;
  assert.ok(!('ecosystem' in odd.sources[0]));
});

test('ecosystem のない既存の情報源: 内容が同じでも ecosystem だけが足され、fetched_at は変わらない', () => {
  const old = mergeAdvisories({ previous: [], records: [fromOsv(ghsaPyPI(), { now: NOW })], now: NOW }).values().next().value;
  assert.ok(!('ecosystem' in old.sources[0]));
  const later = mergeAdvisories({ previous: [old], records: [fromOsv(ghsaPyPI(), { now: '2026-11-25T00:00:00Z', dbEcosystem: 'PyPI' })], now: '2026-11-25T00:00:00Z' }).values().next().value;
  assert.equal(later.sources[0].ecosystem, 'PyPI');
  assert.equal(later.sources[0].fetched_at, NOW);
});

test('osvSourceEcosystem: source.ecosystem → affected の osv 由来の要素 → advisory.ecosystem の順', () => {
  const base = { ecosystem: 'python', affected: [
    { package: { ecosystem: 'python' }, from_sources: ['python-psf:PSF-1'] }, { package: { ecosystem: 'PyPI' }, from_sources: ['osv:GHSA-x'] }] };
  assert.equal(osvSourceEcosystem(base, { id: 'GHSA-x' }), 'PyPI');
  assert.equal(osvSourceEcosystem(base, { id: 'GHSA-x', ecosystem: 'npm' }), 'npm');
  assert.equal(osvSourceEcosystem(base, { id: 'GHSA-none' }), 'python');
  assert.equal(osvSourceEcosystem({ ecosystem: 'npm', affected: [] }, { id: 'GHSA-y' }), 'npm', '既存の dependency は advisory.ecosystem のまま');
  const two = { ecosystem: 'npm', affected: [{ package: { ecosystem: 'npm' }, from_sources: ['osv:G'] }, { package: { ecosystem: 'PyPI' }, from_sources: ['osv:G'] }] };
  assert.equal(osvSourceEcosystem(two, { id: 'G' }), 'npm', '1つに決まらなければ advisory.ecosystem');
});

test('定期更新: PSF が先で category が runtime のままでも、PyPI の zip から読み直され、影響範囲の更新が反映される', async () => {
  const psfFirst = await run({ 'python-psf': okPsf([psfRecord('PSF-2026-9', TAGS_3_12)]) });
  // PyPI の記録を統合（スキャナ由来）してから、PyPI の zip の更新を追う
  const withPyPI = mergeAdvisories({ previous: [...psfFirst.advisories.values()], records: [fromOsv(ghsaPyPI(), { now: NOW, dbEcosystem: 'PyPI' })], now: NOW });
  const stored = [...new Map([...psfFirst.advisories, ...withPyPI]).values()];
  const updated = ghsaPyPI({ affected: [{ package: { ecosystem: 'PyPI', name: 'pkg' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '3.0.0' }] }] }] });
  const next = await run({}, emptyData({ advisories: stored }), { osvDbDir: makeDb({ PyPI: [updated] }), now: '2026-11-20T03:00:00Z' });
  const advisory = next.advisories.get('CVE-2026-2297') ?? [...next.advisories.values()].find((a) => a.aliases.cve.includes('CVE-2026-2297'));
  const pypi = advisory.affected.find((a) => a.package.ecosystem === 'PyPI');
  assert.equal(pypi.ranges[0].events.at(-1).fixed, '3.0.0');
  assert.ok(advisory.affected.some((a) => a.package.ecosystem === 'python'), 'python の要素は残る');
});

test('定期更新: 取り下げ → 撤回の遷移（PSF が先の順）で、PyPI の要素が消え、次の回も PyPI の zip から読み直されて戻る', async () => {
  const psfFirst = await run({ 'python-psf': okPsf([psfRecord('PSF-2026-9', TAGS_3_12)]) });
  const seeded = mergeAdvisories({ previous: [...psfFirst.advisories.values()], records: [fromOsv(ghsaPyPI(), { now: NOW, dbEcosystem: 'PyPI' })], now: NOW });
  let advisories = [...seeded.values()];
  const step = async (zipRecords, now) => {
    const norm = await run({}, emptyData({ advisories }), { osvDbDir: makeDb({ PyPI: zipRecords }), now });
    advisories = [...new Map([...advisories.map((a) => [a.key, a]), ...norm.advisories]).values()];
    return advisories.find((a) => !a.superseded_by && a.aliases.cve.includes('CVE-2026-2297') || a.key === 'CVE-2026-2297');
  };
  const gone = await step([ghsaPyPI({ withdrawn: '2026-11-10T00:00:00Z', affected: undefined })], '2026-11-20T03:00:00Z');
  assert.ok(!gone.affected.some((a) => a.package.ecosystem === 'PyPI'));
  assert.equal(gone.sources.find((s) => s.name === 'osv').ecosystem, 'PyPI');
  const stillGone = await step([ghsaPyPI({ withdrawn: '2026-11-10T00:00:00Z', affected: undefined })], '2026-11-21T03:00:00Z');
  assert.ok(!stillGone.affected.some((a) => a.package.ecosystem === 'PyPI'));
  const back = await step([ghsaPyPI()], '2026-11-22T03:00:00Z');
  assert.ok(back.affected.some((a) => a.package.ecosystem === 'PyPI'), '撤回で PyPI の要素が戻る');
});

test('定期更新: 既存の dependency（npm）のアドバイザリは、変更前と同じ zip から読み直される', async () => {
  const npmAdvisory = mergeAdvisories({ previous: [], records: [fromOsv(osvRecord(), { now: NOW })], now: NOW }).values().next().value;
  const changed = osvRecord({ affected: [{ package: { ecosystem: 'npm', name: 'example-package' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.9.9' }] }] }] });
  const norm = await run({}, emptyData({ advisories: [npmAdvisory] }), { osvDbDir: makeDb({ npm: [changed] }) });
  assert.equal(norm.advisories.get(npmAdvisory.key).affected[0].ranges[0].events.at(-1).fixed, '1.9.9');
  assert.equal(norm.advisories.get(npmAdvisory.key).sources[0].ecosystem, 'npm');
  const skipped = await run({}, emptyData({ advisories: [npmAdvisory] }), { osvDbDir: makeDb({ npm: [changed] }), osvFetchedThisRun: { npm: false, Packagist: true, PyPI: true } });
  assert.deepEqual([...skipped.advisories.values()], [npmAdvisory], 'その回に取得できなかった DB からは読み直さない');
});

// ---- 単体: branchOf・health ------------------------------------------------------------------

test('branchOf: python は メジャー.マイナー。php・node は変わらない', () => {
  assert.equal(branchOf('python', '3.12.7'), '3.12');
  assert.equal(branchOf('php', '8.2.30'), '8.2');
  assert.equal(branchOf('node', '22.11.0'), '22');
});

test('buildPythonRuntime: python.json が前回なしで pythonReleases もなければ branches は空、pending は前回の値（なければ []）', () => {
  const python = buildPythonRuntime({ previous: null, pythonReleases: null, endoflife: null, advisories: [], pending: null, now: NOW });
  assert.deepEqual([python.branches, python.pending, python.psf_synced_at], [[], [], null]);
  assertValid('runtimes', python);
});

test('health: since が37時間前の pending は問題に出て、12時間前のものは出ない。no_versions には対処を添える', () => {
  const base = { findingsByProject: new Map(), sourceResults: {}, stale: [], now: NOW };
  const old = [{ id: 'PSF-2026-1', reason: 'no_versions', since: '2026-11-17T14:00:00Z' }, { id: 'PSF-2026-2', reason: 'osv_missing', since: '2026-11-19T15:00:00Z'.replace('15', '00') }];
  const problems = collectProblems({ ...base, pythonPending: [old[0], { id: 'PSF-2026-3', reason: 'osv_missing', since: '2026-11-18T15:00:00Z' }] });
  assert.equal(problems.length, 1);
  assert.match(problems[0], /PSF-2026-1（no_versions、2026-11-17T14:00:00Z から）/);
  assert.match(problems[0], /config\/python-no-release-impact\.json/);
  assert.ok(!problems[0].includes('PSF-2026-3'));
  assert.deepEqual(collectProblems({ ...base, pythonPending: [old[1]] }), []);
  assert.deepEqual(collectProblems({ ...base }), []);
});

test('同じ CVE の PSF の記録が Node.js 本体のアドバイザリに統合されても、nodejs.json の範囲・修正版に Python のものが混ざらない', () => {
  const nodeCore = fromNodeCore({ id: '13', sha: 'sha-13', cve: ['CVE-2026-2297'], vulnerable: '<4.8.2', patched: '>=4.8.2', severity: 'high', ref: null, description: 'zlib' }, { now: NOW });
  const first = mergeAdvisories({ previous: [], records: [nodeCore], now: NOW });
  const merged = mergeAdvisories({ previous: [...first.values()], records: [convert(psfRecord('PSF-2017-2', TAGS_3_12)).record], now: NOW });
  const advisory = [...merged.values()].find((a) => !a.superseded_by);
  assert.deepEqual([advisory.category, advisory.ecosystem], ['runtime', 'node'], '先にあった Node.js のアドバイザリのまま');
  assert.deepEqual(advisory.affected.map((a) => a.package.ecosystem).sort(), ['node', 'python']);
  const node = buildNodeRuntime({ previous: null, now: NOW, advisories: [advisory], nodeDist: [{ version: 'v24.22.1' }], endoflife: [] });
  assert.deepEqual(node.advisories[0].ranges.map((r) => r.type), ['NODE_SEMVER'], 'PY_VERSIONS を混ぜない');
  assert.deepEqual(node.advisories[0].fixed_versions, ['4.8.2'], 'Python の修正版を混ぜない');
  const [python] = pythonRuntimeAdvisories([advisory]);
  assert.deepEqual(python.ranges.map((r) => r.type), ['PY_VERSIONS'], 'Python 側にも NODE_SEMVER を混ぜない');
});
