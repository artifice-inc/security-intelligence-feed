import test from 'node:test';
import assert from 'node:assert/strict';
import { fakeHttp, fixtureText } from './helpers/fake-http.mjs';
import { INDEX_URL, detailUrl, collect } from '../src/collect/alas.mjs';
import { buildAmazonLinuxKernel, toStoredCve } from '../src/normalize/amazon-linux-kernel.mjs';
import { kevLinuxCvesOf } from '../src/publish/stage-collect.mjs';
import { collectProblems } from '../src/publish/health.mjs';
import { validate } from '../src/lib/schema.mjs';
import { loadThresholds } from '../src/lib/config.mjs';
import { makeHarness, failing, T0, T1 } from './helpers/central-harness.mjs';

const NOW = '2026-10-30T09:00:00Z';
const THRESHOLDS = { ...loadThresholds(), kernel_fixed_review_days: 30 };
const AV_NET = 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H';
const AV_LOCAL = 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H';
const NOT_FOUND = Object.assign(new Error('HTTP 404'), { kind: 'http_status', http_status: 404 });
const SERVER_ERROR = Object.assign(new Error('HTTP 500'), { kind: 'http_status', http_status: 500 });
const real = JSON.parse(fixtureText('alas-cve-2026-98432.json'));

const entry = (cve_id, modified_date, description = 'In the Linux kernel, x') => ({ cve_id, description, public_date: modified_date, modified_date });
// 1,000件の下限を満たすための、対象外の埋め草（カーネルではない）
const filler = Array.from({ length: 1000 }, (_, i) => entry(`CVE-2020-${String(i + 1).padStart(5, '0')}`, '2020-01-01', 'Other product'));
const indexOf = (...entries) => [...filler, ...entries];
const detail = (cve_id, { severity = 'Critical', vector = AV_LOCAL, modified_date = '2026-10-29', packages } = {}) => ({
  cve_id, public_date: '2026-10-01', modified_date, severity, scores: [{ type: 'CVSSv3', source: 'AMAZON_LINUX', vector }],
  affected_packages: packages ?? [{ name: 'kernel6.18', platform: 'amzn2023', advisories: [], status: 'PendingFix', opt_in_repo: null }],
});
const http = (index, details) => fakeHttp({ [INDEX_URL]: index, ...Object.fromEntries(Object.entries(details).map(([id, v]) => [detailUrl(id), v])) });
// 404 が5%を超えないよう、成功する CVE を20件足す（古い日付なので cursor の続きにだけ入る）
const bulk = Array.from({ length: 20 }, (_, i) => `CVE-2025-${String(i + 1).padStart(4, '0')}`);
const bulkIndex = bulk.map((id) => entry(id, '2025-01-01'));
const bulkDetails = Object.fromEntries(bulk.map((id) => [id, detail(id, { severity: 'Low' })]));
const run = (h, extra = {}) => collect({ http: h, now: NOW, maxPerRun: 100, concurrency: 4, ...extra });
const build = (result, previous = null, extra = {}) => buildAmazonLinuxKernel({ previous, result, kevRecords: extra.kevRecords ?? [], now: extra.now ?? NOW, thresholds: THRESHOLDS });

test('実物の JSON を保存形式に変換し、スキーマを通る。NotAffected は除き、ALAS の文章は持ち込まない', () => {
  const stored = toStoredCve({ ...real, description: 'SECRET TEXT', affected_packages: [...real.affected_packages, { name: 'kernel', platform: 'amzn2', advisories: [], status: 'NotAffected', opt_in_repo: 'kernel-5.4' }] });
  assert.deepEqual(stored.packages.map((p) => p.key), ['amzn2/kernel', 'amzn2/kernel@kernel-5.10', 'amzn2023/kernel6.18']);
  assert.deepEqual(stored.packages[2], { key: 'amzn2023/kernel6.18', status: 'Fixed', advisory: 'ALAS2023-2026-3251', advisory_url: 'https://alas.aws.amazon.com/AL2023/ALAS2023-2026-3251.html', released: '2026-10-24' });
  assert.equal(stored.url, 'https://explore.alas.aws.amazon.com/CVE-2026-98432.html');
  assert.ok(!JSON.stringify(stored).includes('SECRET'));
  const out = build({ ok: true, records: [real], meta: { cursor: null, backfill_complete: true, last_success_date: '2026-10-30', retry: [] } });
  assert.equal(validate('amazon-linux-kernel', out).ok, true, JSON.stringify(validate('amazon-linux-kernel', out).errors));
  assert.deepEqual(out.known_packages, ['amzn2/kernel', 'amzn2/kernel@kernel-5.10', 'amzn2023/kernel6.18']);
});

test('toStoredCve: advisories が複数なら最も古い release_date を使う。空なら3つとも null', () => {
  const stored = toStoredCve(detail('CVE-2026-1', { packages: [
    { name: 'kernel6.12', platform: 'amzn2023', status: 'Fixed', opt_in_repo: null, advisories: [{ id: 'B', url: 'u-b', release_date: '2026-10-20' }, { id: 'A', url: 'u-a', release_date: '2026-10-10' }] },
    { name: 'kernel', platform: 'amzn2', status: 'PendingFix', opt_in_repo: null, advisories: [] },
  ] }));
  assert.deepEqual(stored.packages.find((p) => p.key === 'amzn2023/kernel6.12'), { key: 'amzn2023/kernel6.12', status: 'Fixed', advisory: 'A', advisory_url: 'u-a', released: '2026-10-10' });
  assert.deepEqual(stored.packages.find((p) => p.key === 'amzn2/kernel'), { key: 'amzn2/kernel', status: 'PendingFix', advisory: null, advisory_url: null, released: null });
});

test('cursor: 初回は maxPerRun 件だけ取り、2回目は続きから。尽きたら backfill_complete が true になり、その後も true', async () => {
  const ids = ['CVE-2026-0001', 'CVE-2026-0002', 'CVE-2026-0003'];
  const index = indexOf(...ids.map((id, i) => entry(id, `2026-10-0${i + 1}`)));
  const details = Object.fromEntries(ids.map((id) => [id, detail(id)]));
  const first = await run(http(index, details), { maxPerRun: 2 });
  assert.deepEqual(first.records.map((r) => r.cve_id), ['CVE-2026-0001', 'CVE-2026-0002']);
  assert.deepEqual(first.meta.cursor, { modified_date: '2026-10-02', cve_id: 'CVE-2026-0002' });
  assert.equal(first.meta.backfill_complete, false);
  const previous = build(first);
  const second = await run(http(index, details), { maxPerRun: 2, previous });
  assert.ok(second.records.some((r) => r.cve_id === 'CVE-2026-0003'));
  assert.equal(second.meta.backfill_complete, true);
  const third = await run(http(index, details), { maxPerRun: 2, previous: build(second, previous) });
  assert.equal(third.meta.backfill_complete, true);
  assert.deepEqual(third.meta.cursor, second.meta.cursor);
});

test('404: retry に入り cursor は越える。次の回で取れたら cves に入り retry から外れ、backfill 完了後も取り直される', async () => {
  const index = indexOf(...bulkIndex, entry('CVE-2026-0001', '2026-10-01'), entry('CVE-2026-0002', '2026-10-02'));
  const first = await run(http(index, { ...bulkDetails, 'CVE-2026-0001': NOT_FOUND, 'CVE-2026-0002': detail('CVE-2026-0002') }), { maxPerRun: 1000 });
  assert.equal(first.ok, true);
  assert.deepEqual(first.meta.retry, [{ cve: 'CVE-2026-0001', since: '2026-10-30' }]);
  assert.equal(first.meta.cursor.cve_id, 'CVE-2026-0002');
  assert.equal(first.meta.backfill_complete, true);
  const stored = build(first);
  assert.deepEqual(stored.cves.map((c) => c.cve), ['CVE-2026-0002']);
  const h = http(index, { 'CVE-2026-0001': detail('CVE-2026-0001'), 'CVE-2026-0002': detail('CVE-2026-0002') });
  const second = await run(h, { previous: stored, now: '2026-10-31T09:00:00Z' });
  assert.ok(h.requested.includes(detailUrl('CVE-2026-0001')));
  assert.deepEqual(second.meta.retry, []);
  assert.deepEqual(build(second, stored).cves.map((c) => c.cve), ['CVE-2026-0001', 'CVE-2026-0002']);
});

test('404 が続く間は since を前の値のまま保つ。index から消えたものは retry から外れる', async () => {
  const index = indexOf(...bulkIndex, entry('CVE-2026-0001', '2026-10-01'));
  const previous = { ...build({ ok: true, records: [], meta: { cursor: { modified_date: '2026-10-01', cve_id: 'CVE-2026-0001' }, backfill_complete: true, last_success_date: '2026-10-28', retry: [] } }), retry: [{ cve: 'CVE-2026-0001', since: '2026-10-28' }, { cve: 'CVE-2026-0009', since: '2026-10-28' }] };
  // retry の 20 倍の取り直しが要るので、続きも取って 5% を満たす
  const result = await run(http(index, { ...bulkDetails, 'CVE-2026-0001': NOT_FOUND }), { previous: { ...previous, cursor: null } });
  assert.deepEqual(result.meta.retry, [{ cve: 'CVE-2026-0001', since: '2026-10-28' }]);
});

test('KEV: cursor より前で modified_date が古い CVE も、KEV に載ればその回に取得され、Medium でも残る', async () => {
  const index = indexOf(entry('CVE-2020-9999', '2020-05-01', 'Old kernel entry'), entry('CVE-2026-0001', '2026-10-01'));
  const previous = build({ ok: true, records: [], meta: { cursor: { modified_date: '2026-10-01', cve_id: 'CVE-2026-0001' }, backfill_complete: true, last_success_date: '2026-10-30', retry: [] } });
  const medium = detail('CVE-2020-9999', { severity: 'Medium', modified_date: '2020-05-01' });
  const h = http(index, { 'CVE-2020-9999': medium });
  const result = await run(h, { previous, kevLinuxCves: new Set(['CVE-2020-9999']) });
  assert.deepEqual(result.records.map((r) => r.cve_id), ['CVE-2020-9999']);
  const out = build(result, previous, { kevRecords: [{ cveID: 'CVE-2020-9999' }] });
  assert.deepEqual(out.cves.map((c) => [c.cve, c.kev]), [['CVE-2020-9999', true]]);
  // KEV から外れた回は、次の回の絞り込みで消える
  assert.deepEqual(build({ ok: true, records: [], meta: result.meta }, out, { kevRecords: [] }).cves, []);
});

test('KEV の取得に失敗した回（kevRecords が null）は、前回の kev を引き継ぐ', () => {
  const previous = build({ ok: true, records: [detail('CVE-2026-0001', { severity: 'Low' })], meta: { cursor: null, backfill_complete: true, last_success_date: '2026-10-30', retry: [] } }, null, { kevRecords: [{ cveID: 'CVE-2026-0001' }] });
  assert.equal(previous.cves[0].kev, true);
  const next = buildAmazonLinuxKernel({ previous, result: { ok: true, records: [], meta: { cursor: null, backfill_complete: true, last_success_date: '2026-10-31', retry: [] } }, kevRecords: null, now: NOW, thresholds: THRESHOLDS });
  assert.deepEqual(next.cves.map((c) => c.cve), ['CVE-2026-0001']);
  const kevSet = kevLinuxCvesOf({ ok: false }, previous);
  assert.deepEqual([...kevSet], ['CVE-2026-0001']);
  assert.deepEqual([...kevLinuxCvesOf({ ok: true, records: [{ cveID: 'CVE-1', vendorProject: 'Linux', product: 'Kernel' }, { cveID: 'CVE-2', vendorProject: 'Linux', product: 'Other' }] }, null)], ['CVE-1']);
});

test('停止期間: 10-30 に成功したあと、10-30 付けの小さい ID が更新されても、11-02 の回で取り直される', async () => {
  const index1 = indexOf(entry('CVE-2026-0900', '2026-10-30'));
  const first = await run(http(index1, { 'CVE-2026-0900': detail('CVE-2026-0900', { modified_date: '2026-10-30' }) }));
  const previous = build(first);
  assert.equal(previous.last_success_date, '2026-10-30');
  const index2 = indexOf(entry('CVE-2026-0900', '2026-10-30'), entry('CVE-2026-0100', '2026-10-30'));
  const h = http(index2, { 'CVE-2026-0100': detail('CVE-2026-0100', { modified_date: '2026-10-30' }), 'CVE-2026-0900': detail('CVE-2026-0900') });
  const second = await run(h, { previous, now: '2026-11-02T09:00:00Z' });
  assert.ok(second.records.some((r) => r.cve_id === 'CVE-2026-0100'), '10-30 付けの小さい ID（cursor より前）が取得される');
  assert.equal(second.meta.last_success_date, '2026-11-02');
});

test('失敗した回は meta を返さず、前回のデータ・cursor・updated_at・last_success_date・retry がそのまま残る', async () => {
  const index = indexOf(entry('CVE-2026-0001', '2026-10-30'));
  const previous = build(await run(http(index, { 'CVE-2026-0001': detail('CVE-2026-0001') })));
  const failed = await run(http(index, { 'CVE-2026-0001': SERVER_ERROR }), { previous });
  assert.equal(failed.ok, false);
  assert.equal(failed.meta, undefined);
  assert.deepEqual(build(failed, previous, { now: '2026-11-05T00:00:00Z' }), previous);
  // 失敗が続いた日数ぶん、次の回の取り直しの期間が広がる（起点は前回成功の前日のまま）
  const index2 = indexOf(entry('CVE-2026-0001', '2026-10-30'), entry('CVE-2026-0050', '2026-10-31'));
  const h = http(index2, { 'CVE-2026-0001': detail('CVE-2026-0001'), 'CVE-2026-0050': detail('CVE-2026-0050') });
  const next = await run(h, { previous, now: '2026-11-05T09:00:00Z' });
  assert.ok(next.records.some((r) => r.cve_id === 'CVE-2026-0050'));
});

test('失敗: index が配列でない・1,000件未満・CVE の取得が 500', async () => {
  assert.equal((await run(http({ not: 'array' }, {}))).ok, false);
  const small = await run(http([entry('CVE-2026-0001', '2026-10-01')], {}));
  assert.equal(small.ok, false);
  assert.equal(small.error.kind, 'parse');
  const index = indexOf(entry('CVE-2026-0001', '2026-10-01'));
  assert.equal((await run(http(index, { 'CVE-2026-0001': SERVER_ERROR }))).ok, false);
});

test('404 は5%以下なら続行し、5%を超えたら失敗する', async () => {
  const ids = Array.from({ length: 20 }, (_, i) => `CVE-2026-${String(i + 1).padStart(4, '0')}`);
  const index = indexOf(...ids.map((id, i) => entry(id, `2026-09-${String(i + 1).padStart(2, '0')}`)));
  const okDetails = Object.fromEntries(ids.map((id) => [id, detail(id)]));
  const one = await run(http(index, { ...okDetails, [ids[0]]: NOT_FOUND }));
  assert.equal(one.ok, true, '1/20 = 5% は続行');
  const two = await run(http(index, { ...okDetails, [ids[0]]: NOT_FOUND, [ids[1]]: NOT_FOUND }));
  assert.equal(two.ok, false, '2/20 = 10% は失敗');
});

test('不正な cve_id（../x など）は URL に入れない', async () => {
  const index = indexOf(entry('../x', '2026-10-01'), entry('CVE-2026-0001', '2026-10-01'));
  const h = http(index, { 'CVE-2026-0001': detail('CVE-2026-0001') });
  const result = await run(h);
  assert.equal(result.ok, true);
  assert.ok(h.requested.every((u) => !u.includes('..')));
});

test('保存形式での再判定: Important + AV:N/PR:N/UI:N は取得しなかった次の回も残る。2つの scores の片方だけ条件を満たしても残る', () => {
  const meta = { cursor: null, backfill_complete: true, last_success_date: '2026-10-30', retry: [] };
  const two = { ...detail('CVE-2026-0002', { severity: 'Important', vector: AV_LOCAL }), scores: [{ vector: AV_LOCAL }, { vector: AV_NET }] };
  const first = build({ ok: true, records: [detail('CVE-2026-0001', { severity: 'Important', vector: AV_NET }), two], meta });
  assert.deepEqual(first.cves.map((c) => c.cve), ['CVE-2026-0001', 'CVE-2026-0002']);
  const second = build({ ok: true, records: [], meta }, first);
  assert.deepEqual(second.cves, first.cves);
});

test('絞り込み: Important+AV:L は捨て、Critical+AV:L は残し、Medium+KEV は残す', () => {
  const meta = { cursor: null, backfill_complete: true, last_success_date: '2026-10-30', retry: [] };
  const records = [
    detail('CVE-2026-0001', { severity: 'Important', vector: AV_LOCAL }), detail('CVE-2026-0002', { severity: 'Critical', vector: AV_LOCAL }),
    detail('CVE-2026-0003', { severity: 'Medium', vector: AV_LOCAL }), detail('CVE-2026-0004', { severity: 'Medium', vector: AV_LOCAL }),
  ];
  const out = build({ ok: true, records, meta }, null, { kevRecords: [{ cveID: 'CVE-2026-0003' }] });
  assert.deepEqual(out.cves.map((c) => c.cve), ['CVE-2026-0002', 'CVE-2026-0003']);
});

test('Fixed: 31日前は捨て、29日前は残し、released が null は残し、未知の status・PendingFix・NoFixPlanned は残す。KEV でも例外にしない', () => {
  const pkg = (name, status, release_date) => ({ name, platform: 'amzn2023', status, opt_in_repo: null, advisories: release_date ? [{ id: 'A', url: 'u', release_date }] : [] });
  const meta = { cursor: null, backfill_complete: true, last_success_date: '2026-10-30', retry: [] };
  const records = [detail('CVE-2026-0001', { packages: [pkg('old', 'Fixed', '2026-09-29'), pkg('recent', 'Fixed', '2026-10-01'), pkg('nodate', 'Fixed'), pkg('weird', 'Strange'), pkg('pend', 'PendingFix'), pkg('nofix', 'NoFixPlanned')] }), detail('CVE-2026-0002', { packages: [pkg('old', 'Fixed', '2026-09-29')] })];
  const out = build({ ok: true, records, meta }, null, { kevRecords: [{ cveID: 'CVE-2026-0002' }] });
  assert.deepEqual(out.cves.map((c) => c.cve), ['CVE-2026-0001']);
  assert.deepEqual(out.cves[0].packages.map((p) => p.key), ['amzn2023/nodate', 'amzn2023/nofix', 'amzn2023/pend', 'amzn2023/recent', 'amzn2023/weird']);
});

test('保存済みの Fixed は、取得しない回でも期限を過ぎたら外れる（29日前 → 2日後）', () => {
  const meta = { cursor: null, backfill_complete: true, last_success_date: '2026-10-30', retry: [] };
  const pkg = { name: 'k', platform: 'amzn2023', status: 'Fixed', opt_in_repo: null, advisories: [{ id: 'A', url: 'u', release_date: '2026-10-01' }] };
  const stored = build({ ok: true, records: [detail('CVE-2026-0001', { packages: [pkg] })], meta });
  assert.equal(stored.cves.length, 1);
  const later = build({ ok: true, records: [], meta }, stored, { now: '2026-11-01T09:00:00Z' });
  assert.deepEqual(later.cves, []);
});

test('冪等: 同じ入力で2回実行すると同じ出力（updated_at も変わらない）。cursor だけの変化では updated_at を動かさない', () => {
  const meta = { cursor: null, backfill_complete: false, last_success_date: '2026-10-30', retry: [] };
  const result = { ok: true, records: [real], meta };
  const once = build(result);
  const twice = build(result, once, { now: '2026-10-31T00:00:00Z' });
  assert.deepEqual(twice, { ...once });
  const moved = build({ ok: true, records: [], meta: { ...meta, cursor: { modified_date: '2026-10-30', cve_id: 'CVE-2026-1' } } }, once, { now: '2026-11-01T00:00:00Z' });
  assert.equal(moved.updated_at, once.updated_at);
  assert.equal(moved.cursor.cve_id, 'CVE-2026-1');
});

test('health: retry に stale_source_hours より古いものがあると問題に出る。新しいものは出ない', () => {
  const base = { findingsByProject: new Map(), sourceResults: {}, stale: [], now: '2026-10-30T09:00:00Z' };
  const problems = collectProblems({ ...base, alasRetry: [{ cve: 'CVE-2026-0001', since: '2026-10-27' }, { cve: 'CVE-2026-0002', since: '2026-10-30' }] });
  assert.deepEqual(problems, ['ALAS の詳細を取得できない CVE があります: CVE-2026-0001（2026-10-27 から）']);
  assert.deepEqual(collectProblems({ ...base, alasRetry: [{ cve: 'CVE-2026-0002', since: '2026-10-30' }] }), []);
});

test('中央の実行: data/os/amazon-linux-kernel.json が書かれて検証を通り、health.sources に alas が出る。失敗した回は前回のまま partial', async () => {
  const h = makeHarness();
  h.state.collectors.alas = async () => ({ ok: true, records: [real], meta: { cursor: { modified_date: '2026-10-29', cve_id: 'CVE-2026-98432' }, backfill_complete: true, last_success_date: '2026-10-25', retry: [], index_total: 1 } });
  const first = await h.run(T0);
  assert.equal(first.status, 'success');
  assert.equal(h.read('os/amazon-linux-kernel.json').cves[0].cve, 'CVE-2026-98432');
  assert.ok(h.read('health.json').sources.alas.last_success_at);
  const before = h.read('os/amazon-linux-kernel.json');
  h.state.collectors.alas = failing();
  const second = await h.run(T1);
  assert.equal(second.status, 'partial');
  assert.deepEqual(h.read('os/amazon-linux-kernel.json'), before);
});
