import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { makeHarness, scannerStub, T0, T1 } from './helpers/central-harness.mjs';
import { fixtureText } from './helpers/fake-http.mjs';
import { matchKernel } from '../src/match/kernel-match.mjs';
import { assembleItems } from '../src/match/assemble.mjs';
import { buildAmazonLinuxKernel } from '../src/normalize/amazon-linux-kernel.mjs';
import { detectStack } from '../src/inventory/detect-stack.mjs';
import { securityCheck } from '../src/local/security-check.mjs';
import { assertValid } from '../src/lib/schema.mjs';
import { loadThresholds } from '../src/lib/config.mjs';
import { zipPathOf } from '../src/collect/osv-db.mjs';
import { makeTree } from './helpers/tree.mjs';

const real = JSON.parse(fixtureText('alas-cve-2026-98432.json'));
const THRESHOLDS = loadThresholds();
const STACK_AL2023 = 'os: linux\nkernel:\n  distro: amazonlinux\n  release: "2023"\n  package: kernel6.18\n';
const PROJECT_FILES = { 'package-lock.json': '{}', '.nvmrc': '22.11.0', '.security/stack.yml': STACK_AL2023 };
const withPackage = (raw, pkg) => ({ ...raw, affected_packages: [...raw.affected_packages, { advisories: [], opt_in_repo: null, ...pkg }] });
const meta = (extra = {}) => ({ cursor: null, backfill_complete: true, last_success_date: '2026-10-25', retry: [], index_total: 1, ...extra });
const dataOf = (records, kevRecords = [], metaExtra = {}) => buildAmazonLinuxKernel({ previous: null, result: { ok: true, records, meta: meta(metaExtra) }, kevRecords, now: T0, thresholds: THRESHOLDS });
const inv = (kernel) => ({ project: 'demo', kernel });
const al2023 = { distro: 'amazonlinux', release: '2023', package: 'kernel6.18' };
const itemsOf = (detections, exposure = 'internet') => assembleItems({ detections, index: new Map(), exposure, now: T0, provenance: {} });
const alasCollector = (records, metaExtra = {}) => async () => ({ ok: true, records, meta: meta(metaExtra) });

test('申告なし: detections も errors も空', () => {
  assert.deepEqual(matchKernel({ inventory: inv(undefined), kernelData: dataOf([real]) }), { detections: [], errors: [] });
  assert.deepEqual(matchKernel({ inventory: inv(null), kernelData: null }), { detections: [], errors: [] });
});

test('CVE-2026-98432: AL2023 kernel6.18 は Fixed で needs_review（P3）、fixed_versions は ALAS 番号', () => {
  const { detections, errors } = matchKernel({ inventory: inv(al2023), kernelData: dataOf([real]) });
  assert.deepEqual(errors, []);
  const [item] = itemsOf(detections);
  assert.equal(item.judgement, 'needs_review');
  assert.equal(item.priority, 'P3');
  assert.deepEqual(item.fixed_versions, ['ALAS2023-2026-3251']);
  assert.deepEqual(item.locations.map((l) => [l.lockfile, l.package, l.ecosystem, l.installed_version]), [['.security/stack.yml', 'kernel6.18', 'os', 'al2023']]);
  assert.equal(item.title, 'CVE-2026-98432 Linux カーネル（Amazon Linux の重大度 Important）');
  assert.match(item.evidence, /ALAS2023-2026-3251.*2026-10-24.*releasever=latest/);
  assert.deepEqual(item.source_urls, ['https://alas.aws.amazon.com/AL2023/ALAS2023-2026-3251.html', 'https://explore.alas.aws.amazon.com/CVE-2026-98432.html']);
});

test('CVE-2026-98432: AL2 の kernel@kernel-5.10 は affected で、internet なら P1。internal なら P2', () => {
  const kernel = { distro: 'amazonlinux', release: '2', package: 'kernel', repo: 'kernel-5.10' };
  const { detections } = matchKernel({ inventory: inv(kernel), kernelData: dataOf([real]) });
  const [item] = itemsOf(detections);
  assert.equal(item.judgement, 'affected');
  assert.equal(item.priority, 'P1');
  assert.equal(item.locations[0].package, 'kernel@kernel-5.10');
  assert.equal(item.locations[0].installed_version, 'al2');
  assert.equal(itemsOf(detections, 'internal')[0].priority, 'P2');
});

test('amzn2023/kernel は PendingFix で affected', () => {
  const raw = withPackage(real, { name: 'kernel', platform: 'amzn2023', status: 'PendingFix' });
  const { detections } = matchKernel({ inventory: inv({ ...al2023, package: 'kernel' }), kernelData: dataOf([raw]) });
  assert.equal(detections[0].judgement, 'affected');
  assert.match(detections[0].evidence, /PendingFix/);
});

test('KEV は kev_hint 経由で P0。NoFixPlanned は affected。未知の status は needs_review', () => {
  const pend = (cve_id, status) => ({ cve_id, severity: 'Critical', scores: [], affected_packages: [{ name: 'kernel6.18', platform: 'amzn2023', advisories: [], status, opt_in_repo: null }] });
  const data = dataOf([pend('CVE-2026-0001', 'PendingFix'), pend('CVE-2026-0002', 'NoFixPlanned'), pend('CVE-2026-0003', 'Weird')], [{ cveID: 'CVE-2026-0001' }]);
  const items = Object.fromEntries(itemsOf(matchKernel({ inventory: inv(al2023), kernelData: data }).detections).map((i) => [i.advisory_key, i]));
  assert.equal(items['CVE-2026-0001'].priority, 'P0');
  assert.equal(items['CVE-2026-0001'].kev, true);
  assert.equal(items['CVE-2026-0002'].judgement, 'affected');
  assert.match(items['CVE-2026-0002'].evidence, /NoFixPlanned/);
  assert.equal(items['CVE-2026-0003'].judgement, 'needs_review');
  assert.match(items['CVE-2026-0003'].evidence, /Weird.*解釈できません/);
});

test('取り込み中・データなし・申告のキーが不明は errors が1件', () => {
  for (const kernelData of [null, dataOf([real], [], { backfill_complete: false })]) {
    const r = matchKernel({ inventory: inv(al2023), kernelData });
    assert.deepEqual(r.detections, []);
    assert.equal(r.errors.length, 1);
    assert.equal(r.errors[0].kind, 'source');
  }
  const unknown = matchKernel({ inventory: inv({ ...al2023, package: 'kernel9.9' }), kernelData: dataOf([real]) });
  assert.equal(unknown.errors.length, 1);
  assert.deepEqual([unknown.errors[0].kind, unknown.errors[0].target], ['inventory', '.security/stack.yml']);
  assert.match(unknown.errors[0].message, /amzn2023\/kernel9\.9/);
});

test('retry が残る間は detections を返したうえで errors を1件足す（CVE は先頭5件）', () => {
  const retry = Array.from({ length: 7 }, (_, i) => ({ cve: `CVE-2026-000${i + 1}`, since: '2026-10-29' }));
  const r = matchKernel({ inventory: inv(al2023), kernelData: dataOf([real], [], { retry }) });
  assert.equal(r.detections.length, 1);
  assert.equal(r.errors.length, 1);
  assert.match(r.errors[0].message, /7件.*CVE-2026-0001.*CVE-2026-0005/);
  assert.ok(!r.errors[0].message.includes('CVE-2026-0006'));
});

test('stack.yml の kernel が不完全（package がない）なら stack.yml 全体が無視され、problems に出る', () => {
  const root = makeTree({ '.security/stack.yml': 'os: linux\nruntimes:\n  node: "22.11.0"\nkernel:\n  distro: amazonlinux\n  release: "2023"\n', 'package-lock.json': '{}' });
  const detected = detectStack(root);
  assert.equal(detected.stack, null);
  assert.ok(detected.problems.some((p) => p.target === '.security/stack.yml' && /スキーマに合いません/.test(p.message)));
  const ok = detectStack(makeTree({ '.security/stack.yml': STACK_AL2023, 'package-lock.json': '{}' }));
  assert.deepEqual(ok.stack.kernel, al2023);
});

// --- 中央の実行 ---
const findingsOf = (h) => h.read('findings/demo.json');

test('中央: 申告した案件に CVE が出て complete。申告していない案件の findings は、カーネルのデータの有無で変わらない', async () => {
  const declared = makeHarness({ projectFiles: PROJECT_FILES });
  declared.state.collectors.alas = alasCollector([real]);
  assert.equal((await declared.run(T0)).status, 'success');
  const f = findingsOf(declared);
  assert.equal(f.scan_status, 'complete');
  assert.deepEqual(f.items.map((i) => [i.advisory_key, i.judgement, i.priority, i.locations[0].ecosystem]), [['CVE-2026-98432', 'needs_review', 'P3', 'os']]);
  assert.deepEqual(declared.read('inventory/demo.json').kernel, al2023);

  // 回帰: 申告なしの案件は、カーネルのデータがあってもなくても findings・inventory が1バイトも変わらない
  const plain = async (alas) => {
    const h = makeHarness();
    h.state.vulns = [{ id: 'GHSA-aaaa-bbbb-cccc', aliases: ['CVE-2026-1'], severity: 'HIGH' }];
    if (alas) h.state.collectors.alas = alasCollector([real]);
    await h.run(T0);
    // ハーネスごとにリポジトリが違うので、コミット SHA だけそろえて比べる
    const bytes = (rel) => JSON.stringify(h.read(rel)).replace(/[0-9a-f]{40}/g, '<sha>');
    return { findings: bytes('findings/demo.json'), inventory: bytes('inventory/demo.json') };
  };
  assert.deepEqual(await plain(true), await plain(false));
  assert.ok(!('kernel' in JSON.parse((await plain(false)).inventory)));
});

test('中央: 取り込み中・取得失敗・retry が残る回は partial で、前回の項目が消えない。retry が空になれば complete に戻る', async () => {
  const h = makeHarness({ projectFiles: PROJECT_FILES });
  h.state.collectors.alas = alasCollector([real]);
  await h.run(T0);
  assert.equal(findingsOf(h).items.length, 1);

  h.state.collectors.alas = alasCollector([], { retry: [{ cve: 'CVE-2026-0001', since: '2026-10-25' }] });
  await h.run(T1);
  let f = findingsOf(h);
  assert.equal(f.scan_status, 'partial');
  assert.ok(f.scan_errors.some((e) => e.target === 'alas' && /取得できていない/.test(e.message)));
  assert.equal(f.items.length, 1, '前回の項目が消えない（detections は出る）');

  h.state.collectors.alas = async () => ({ ok: false, records: [], error: { kind: 'network', message: 'down', http_status: null } });
  await h.run('2026-10-25T10:00:00Z');
  f = findingsOf(h);
  assert.equal(f.scan_status, 'partial');
  assert.equal(f.items.length, 1);

  h.state.collectors.alas = alasCollector([]);
  await h.run('2026-10-25T11:00:00Z');
  assert.equal(findingsOf(h).scan_status, 'complete');
});

test('中央: 申告のキーが ALAS のデータにないと inventory エラーで partial（health の問題にも出る）', async () => {
  const h = makeHarness({ projectFiles: { ...PROJECT_FILES, '.security/stack.yml': STACK_AL2023.replace('kernel6.18', 'kernel9.9') } });
  h.state.collectors.alas = alasCollector([real]);
  await h.run(T0);
  const f = findingsOf(h);
  assert.equal(f.scan_status, 'partial');
  assert.deepEqual(f.items, []);
  assert.ok(f.scan_errors.some((e) => e.kind === 'inventory' && /kernel9\.9/.test(e.message)));
});

// --- ローカルの security-check ---
const AFTER = (hours) => new Date(new Date(T0).getTime() + hours * 3_600_000);

async function localSetup() {
  const h = makeHarness({ projectFiles: PROJECT_FILES });
  h.state.collectors.alas = alasCollector([real]);
  await h.run();
  const osvDir = path.join(h.central.root, 'osv-db');
  for (const eco of ['npm', 'Packagist']) { mkdirSync(path.dirname(zipPathOf(osvDir, eco)), { recursive: true }); writeFileSync(zipPathOf(osvDir, eco), 'placeholder'); }
  writeFileSync(path.join(osvDir, 'meta.json'), JSON.stringify({ npm: { fetched_at: T0, sha256: 'a'.repeat(64) }, Packagist: { fetched_at: T0, sha256: 'a'.repeat(64) } }));
  const fetchOsvDb = async (o) => ({ meta: JSON.parse(readFileSync(path.join(osvDir, 'meta.json'), 'utf8')), outcomes: Object.fromEntries(o.ecosystems.map((e) => [e, { ok: false, error: { message: 'offline' } }])) });
  const deps = { now: AFTER(1), exec: scannerStub(h.state), scannerPath: 'osv-scanner', scannerVersion: async () => '2.7.0', fetchOsvDb };
  const dataFile = (rel) => path.join(h.central.root, 'data', rel);
  const edit = (rel, fn) => writeFileSync(dataFile(rel), JSON.stringify(fn(JSON.parse(readFileSync(dataFile(rel), 'utf8')))));
  return { h, deps, edit, run: () => securityCheck({ cacheRoot: h.central.root, projectDir: h.project.root, projectName: 'demo', deps, scriptVersion: 'test-sha', exposure: 'internet' }) };
}
const kernelRow = (out) => out.summary.rows.find((r) => r.kind === 'os');

test('ローカル: ok の行が出て、出力がスキーマを通り、手元の項目と中央が一致する', async () => {
  const { run } = await localSetup();
  const out = await run();
  assertValid('security-check-output', out);
  assert.deepEqual([kernelRow(out).target, kernelRow(out).state, kernelRow(out).P3], ['kernel:amzn2023/kernel6.18', 'ok', 1]);
  assert.equal(out.local_scan.complete, true, out.local_scan.reasons.join());
  assert.deepEqual(out.stack.kernel, al2023);
  assert.deepEqual(out.central_diff, { only_local: [], only_central: [] });
});

test('ローカル: データがない・古い・直近の取得失敗・retry があるなら unavailable で、local_scan は不完全', async () => {
  const cases = {
    'データなし': async (s) => { s.edit('os/amazon-linux-kernel.json', () => null); },
    '取り込み中': async (s) => { s.edit('os/amazon-linux-kernel.json', (d) => ({ ...d, backfill_complete: false })); },
    '37時間前の成功': async (s) => { s.deps.now = AFTER(37); },
    '直近の取得に失敗': async (s) => { s.deps.now = AFTER(12); s.edit('health.json', (d) => ({ ...d, sources: { ...d.sources, alas: { ...d.sources.alas, last_error: { kind: 'network', message: 'down', http_status: null, at: AFTER(11).toISOString() } } } })); },
    'retry あり': async (s) => { s.edit('os/amazon-linux-kernel.json', (d) => ({ ...d, retry: [{ cve: 'CVE-2026-0001', since: '2026-10-25' }] })); },
    '申告のキーが不明': async (s) => { s.edit('os/amazon-linux-kernel.json', (d) => ({ ...d, known_packages: [] })); },
  };
  for (const [name, change] of Object.entries(cases)) {
    const s = await localSetup();
    await change(s);
    const out = await s.run();
    assert.equal(kernelRow(out).state, 'unavailable', name);
    assert.equal(out.local_scan.complete, false, name);
    assertValid('security-check-output', out);
  }
});

test('ローカル: retry が空になれば ok に戻る', async () => {
  const s = await localSetup();
  s.edit('os/amazon-linux-kernel.json', (d) => ({ ...d, retry: [{ cve: 'CVE-2026-0001', since: '2026-10-25' }] }));
  assert.equal(kernelRow(await s.run()).state, 'unavailable');
  s.edit('os/amazon-linux-kernel.json', (d) => ({ ...d, retry: [] }));
  assert.equal(kernelRow(await s.run()).state, 'ok');
});

test('ローカル: 中央に開いた KERNEL の Issue があり、手元の結果にカーネルの項目がなくても resolved_locally に入らない（件数には数える）', async () => {
  const s = await localSetup();
  s.edit('os/amazon-linux-kernel.json', (d) => ({ ...d, cves: [] }));
  s.edit('issues.json', () => [
    { project: 'demo', state: 'open', issue_number: 7, aliases: ['KERNEL-al2023-kernel6.18'], labels: ['P1'] },
    { project: 'demo', state: 'open', issue_number: 8, aliases: ['CVE-2026-9'], labels: ['P2'] },
  ]);
  const out = await s.run();
  assert.equal(out.local_scan.complete, true, out.local_scan.reasons.join());
  assert.deepEqual(out.central_issues.resolved_locally.map((c) => c.issue_number), [8]);
  assert.equal(out.central_issues.open.P1, 1);
});
