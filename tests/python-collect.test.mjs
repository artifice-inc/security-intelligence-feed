import test from 'node:test';
import assert from 'node:assert/strict';
import { fakeHttp } from './helpers/fake-http.mjs';
import * as psf from '../src/collect/python-psf.mjs';
import * as releases from '../src/collect/python-releases.mjs';
import * as endoflife from '../src/collect/endoflife.mjs';
import { COLLECTORS } from '../src/collect/index.mjs';
import { COLLECT_HOSTS, OSV_HOSTS, createHttp } from '../src/lib/http.mjs';
import { pythonAffectedVersions, pythonFixedVersions, pythonBranch, comparePython } from '../src/lib/versions-python.mjs';
import { loadPythonNoReleaseImpact } from '../src/lib/python-no-release-impact.mjs';
import { validate } from '../src/lib/schema.mjs';
import { psfRecord, TAGS_3_12, pythonOrgList, releaseRecords } from './helpers/python-fixtures.mjs';

const NOT_FOUND = Object.assign(new Error('HTTP 404'), { kind: 'http_status', http_status: 404 });
const SERVER_ERROR = Object.assign(new Error('HTTP 503'), { kind: 'http_status', http_status: 503 });
const listing = (ids) => ids.map((id) => ({ type: 'file', name: `${id}.json` }));
const osvUrl = (id) => `${psf.OSV_GIT_BASE}/${id}.json`;

test('python-psf: 一覧から ID を取り、OSV の個別の記録を ID の昇順に順に取る', async () => {
  const http = fakeHttp({ [psf.LIST_URL]: listing(['PSF-2026-9', 'PSF-2026-10', 'PSF-2025-1']).concat([{ type: 'dir', name: 'PSF-2026-99.json' }, { type: 'file', name: 'README.md' }]),
    [osvUrl('PSF-2025-1')]: psfRecord('PSF-2025-1', []), [osvUrl('PSF-2026-10')]: psfRecord('PSF-2026-10', []), [osvUrl('PSF-2026-9')]: psfRecord('PSF-2026-9', TAGS_3_12) });
  const result = await psf.collect({ http });
  assert.equal(result.ok, true);
  assert.deepEqual(result.records.map((r) => r.id), ['PSF-2025-1', 'PSF-2026-10', 'PSF-2026-9']);
  assert.deepEqual(result.missing, []);
  assert.deepEqual(http.requested.slice(1), ['PSF-2025-1', 'PSF-2026-10', 'PSF-2026-9'].map(osvUrl), '全件を順に取る');
});

test('python-psf: 不正な名前（../x.json）は取らない。一覧が配列でない・0件なら失敗', async () => {
  const http = fakeHttp({ [psf.LIST_URL]: listing(['PSF-2026-1', '../x', 'PSF-2026-1/../../y']).map((f) => ({ ...f })), [osvUrl('PSF-2026-1')]: psfRecord('PSF-2026-1', []) });
  const result = await psf.collect({ http });
  assert.equal(result.ok, true);
  assert.deepEqual(http.requested, [psf.LIST_URL, osvUrl('PSF-2026-1')]);
  assert.equal((await psf.collect({ http: fakeHttp({ [psf.LIST_URL]: { message: 'x' } }) })).error.kind, 'parse');
  assert.equal((await psf.collect({ http: fakeHttp({ [psf.LIST_URL]: [{ type: 'file', name: 'README.md' }] }) })).ok, false);
});

test('python-psf: 一覧が1,000件なら失敗（Git Trees API への切り替えを知らせる）', async () => {
  const ids = Array.from({ length: 1000 }, (_, i) => `PSF-2026-${i}`);
  const result = await psf.collect({ http: fakeHttp({ [psf.LIST_URL]: listing(ids) }) });
  assert.equal(result.ok, false);
  assert.match(result.error.message, /Git Trees API/);
});

test('python-psf: 404 は missing に入れて ok のまま続ける。404 以外のエラーは収集器全体が失敗', async () => {
  const routes = { [psf.LIST_URL]: listing(Array.from({ length: 40 }, (_, i) => `PSF-2026-${i + 1}`)) };
  for (let i = 1; i <= 40; i += 1) routes[osvUrl(`PSF-2026-${i}`)] = psfRecord(`PSF-2026-${i}`, []);
  routes[osvUrl('PSF-2026-5')] = NOT_FOUND;
  const result = await psf.collect({ http: fakeHttp(routes) });
  assert.equal(result.ok, true);
  assert.deepEqual(result.missing, ['PSF-2026-5']);
  assert.equal(result.records.length, 39);
  routes[osvUrl('PSF-2026-6')] = SERVER_ERROR;
  assert.equal((await psf.collect({ http: fakeHttp(routes) })).ok, false);
});

test('python-psf: 404 が5%を超えたら失敗（取得元の障害）。id が違う記録も失敗', async () => {
  const ids = Array.from({ length: 20 }, (_, i) => `PSF-2026-${i + 1}`);
  const routes = { [psf.LIST_URL]: listing(ids) };
  for (const id of ids) routes[osvUrl(id)] = psfRecord(id, []);
  routes[osvUrl('PSF-2026-1')] = NOT_FOUND; // 1/20 = 5% は許す
  assert.equal((await psf.collect({ http: fakeHttp(routes) })).ok, true);
  routes[osvUrl('PSF-2026-2')] = NOT_FOUND;
  const failed = await psf.collect({ http: fakeHttp(routes) });
  assert.equal(failed.ok, false);
  assert.equal(failed.error.kind, 'parse');
  const wrong = { [psf.LIST_URL]: listing(['PSF-2026-1']), [osvUrl('PSF-2026-1')]: psfRecord('PSF-2026-2', []) };
  assert.equal((await psf.collect({ http: fakeHttp(wrong) })).ok, false);
});

test('python-releases: 正式版だけを { version, date } にする。3系がなければ失敗', async () => {
  const result = await releases.collect({ http: fakeHttp({ [releases.RELEASES_URL]: pythonOrgList() }) });
  assert.equal(result.ok, true);
  const versions = result.records.map((r) => r.version);
  assert.ok(!versions.some((v) => /rc|a|b/.test(v)));
  assert.ok(versions.includes('3.12.14') && versions.includes('2.7.18'));
  assert.deepEqual(result.records.find((r) => r.version === '3.12.14'), { version: '3.12.14', date: '2026-10-01T00:00:00Z' });
  assert.equal((await releases.collect({ http: fakeHttp({ [releases.RELEASES_URL]: { detail: 'x' } }) })).error.kind, 'parse');
  assert.equal((await releases.collect({ http: fakeHttp({ [releases.RELEASES_URL]: [{ name: 'Python 2.7.18', pre_release: false, release_date: '2020-01-01T00:00:00Z' }] }) })).ok, false);
});

test('endoflife: PRODUCTS は変えず、Python の取得失敗は php・nodejs の収集器に波及しない', async () => {
  assert.deepEqual(endoflife.PRODUCTS, ['php', 'nodejs']);
  const body = (name) => ({ result: { releases: [{ name, isEol: false, eolFrom: '2030-01-01', isLts: false, latest: { name: `${name}.1` } }] } });
  const url = (p) => `https://endoflife.date/api/v1/products/${p}`;
  const phpNode = fakeHttp({ [url('php')]: body('8.3'), [url('nodejs')]: body('22') });
  const ok = await endoflife.collect({ http: phpNode });
  assert.equal(ok.ok, true);
  assert.deepEqual(phpNode.requested, [url('php'), url('nodejs')], 'python は取りに行かない');
  const python = await endoflife.collectPython({ http: fakeHttp({ [url('python')]: body('3.12') }) });
  assert.deepEqual(python.records.map((r) => [r.product, r.name, r.latest]), [['python', '3.12', '3.12.1']]);
  assert.equal((await endoflife.collectPython({ http: fakeHttp({}) })).ok, false);
  assert.equal(COLLECTORS['endoflife-python'], endoflife.collectPython);
  assert.equal(COLLECTORS.endoflife, endoflife.collect);
  assert.ok('python-psf' in COLLECTORS && 'python-releases' in COLLECTORS);
});

test('COLLECT_HOSTS: python.org と OSV の個別の記録を取れるが、OSV_HOSTS は変えない。許可外のホストは拒否', async () => {
  assert.ok(COLLECT_HOSTS.includes('www.python.org') && COLLECT_HOSTS.includes('osv-vulnerabilities.storage.googleapis.com'));
  assert.deepEqual(OSV_HOSTS, ['osv-vulnerabilities.storage.googleapis.com']);
  const http = createHttp({ allowedHosts: COLLECT_HOSTS, fetchImpl: async () => { throw new Error('実ネットワークに出ない'); }, retries: 1 });
  await assert.rejects(http.getJson('https://evil.example.test/x'), /許可リスト外/);
});

test('pythonAffectedVersions: 正式版のタグだけを重複なし・昇順で返す', () => {
  assert.deepEqual(pythonAffectedVersions(psfRecord('X', TAGS_3_12)), ['3.12.0', '3.12.1', '3.12.7', '3.12.13', '3.13.0']);
  assert.deepEqual(pythonAffectedVersions(psfRecord('X', ['v3.15.0a6', 'v3.12.0rc1', 'v3.12.0b1', '3.12.1', 'v3.12'])), []);
  const two = psfRecord('X', ['v3.12.7', 'v3.9.1']);
  two.affected.push({ package: {}, versions: ['v3.12.7', 'v3.10.0'] });
  assert.deepEqual(pythonAffectedVersions(two), ['3.9.1', '3.10.0', '3.12.7']);
  assert.deepEqual(pythonAffectedVersions({ affected: [] }), []);
  assert.equal(comparePython('3.9.10', '3.10.0'), -1);
  assert.equal(pythonBranch('3.12.7'), '3.12');
  assert.equal(pythonBranch('3.14.0rc1'), null);
});

test('pythonFixedVersions: ブランチごとの次の正式版。猶予期間中・影響のないブランチは入れない', () => {
  const affected = ['3.12.0', '3.12.13', '3.13.0'];
  const opts = (now) => ({ now, graceDays: 7 });
  // 3.12.14 は 2026-11-01 のリリース。3日後は猶予中、8日後は修正版
  assert.deepEqual(pythonFixedVersions(affected, releaseRecords, opts('2026-11-04T00:00:00Z')), []);
  assert.deepEqual(pythonFixedVersions(affected, releaseRecords, opts('2026-11-09T00:00:00Z')), ['3.12.14']);
  assert.deepEqual(pythonFixedVersions(affected, releaseRecords, opts('2026-11-08T00:00:00Z')), ['3.12.14'], '7日ちょうどは猶予明け');
  assert.deepEqual(pythonFixedVersions(['3.12.13'], releaseRecords.filter((r) => r.version !== '3.12.14'), opts('2027-01-01T00:00:00Z')), [], 'rc しかなければ入れない');
  assert.deepEqual(pythonFixedVersions(['3.13.0'], releaseRecords, opts('2027-01-01T00:00:00Z')), [], '次の正式版がないブランチは入れない');
  assert.deepEqual(pythonFixedVersions(['3.12.0', '3.12.7'], [{ version: '3.12.9', date: '2025-01-01T00:00:00Z' }, { version: '3.12.8', date: '2025-01-01T00:00:00Z' }], opts('2026-01-01T00:00:00Z')), ['3.12.8']);
  assert.deepEqual(pythonFixedVersions(['3.12.0'], [{ version: '3.12.1', date: null }], opts('2026-01-01T00:00:00Z')), [], '日付がなければ猶予中として扱う');
});

test('確認済みの一覧: 初期値は §0 の6件で、スキーマを通る。違反は読み込みで例外', () => {
  const list = loadPythonNoReleaseImpact();
  assert.deepEqual(Object.keys(list), ['PSF-2014-6', 'PSF-2017-6', 'PSF-2018-2', 'PSF-2023-3', 'PSF-2023-4', 'PSF-2023-7']);
  for (const id of ['PSF-2014-6', 'PSF-2017-6', 'PSF-2018-2']) assert.deepEqual([list[id].decision, list[id].min_version], ['no_impact', '3.0.0']);
  assert.deepEqual(['PSF-2023-3', 'PSF-2023-7'].map((id) => [list[id].decision, list[id].min_version]), [['no_impact', undefined], ['no_impact', undefined]]);
  assert.equal(list['PSF-2023-4'].decision, 'manual_review');
  const good = { decision: 'no_impact', reason: 'r', checked_at: '2026-11-19' };
  assert.equal(validate('python-no-release-impact', { 'PSF-2026-1': good }).ok, true);
  for (const bad of [{ 'CVE-1': good }, { 'PSF-2026-1': { ...good, reason: '' } }, { 'PSF-2026-1': { ...good, decision: 'maybe' } }, { 'PSF-2026-1': { ...good, min_version: '3' } },
    { 'PSF-2026-1': { ...good, decision: 'manual_review', min_version: '3.0.0' } }, { 'PSF-2026-1': { decision: 'no_impact', reason: 'r' } }, { 'PSF-2026-1': { ...good, checked_at: '昨日' } }]) {
    assert.equal(validate('python-no-release-impact', bad).ok, false, JSON.stringify(bad));
  }
});
