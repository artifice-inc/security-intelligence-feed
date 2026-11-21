import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { makeHarness, T0, T1, scannerStub } from './helpers/central-harness.mjs';
import { updateRepo, makeTree } from './helpers/tree.mjs';
import { securityCheck } from '../src/local/security-check.mjs';
import { exportInventory } from '../src/inventory/export-inventory.mjs';
import { assertValid } from '../src/lib/schema.mjs';
import { zipPathOf } from '../src/collect/osv-db.mjs';
import { psfRecord } from './helpers/python-fixtures.mjs';

const TAGS = ['v3.12.0', 'v3.12.7', 'v3.12.13'];
const T2 = '2026-10-25T18:00:00Z';

// 中央の収集を Python 用にそろえる（CPython 3.12 系。3.12.7 は影響あり、3.12.14 は修正版）
function pythonHarness(projectFiles = { '.python-version': '3.12.7\n' }) {
  const h = makeHarness({ projectFiles });
  h.state.collectors['python-psf'] = async () => ({ ok: true, records: [psfRecord('PSF-2026-9', TAGS)], missing: [] });
  h.state.collectors['python-releases'] = async () => ({ ok: true, records: [{ version: '3.12.7', date: '2024-10-01T00:00:00Z' }, { version: '3.12.14', date: '2026-10-01T00:00:00Z' }, { version: '3.12.20', date: '2026-10-24T00:00:00Z' }] });
  h.state.collectors['endoflife-python'] = async () => ({ ok: true, records: [{ product: 'python', name: '3.12', isEol: false, eolFrom: '2028-10-31', isLts: false, latest: '3.12.20' }] });
  return h;
}
const setVersion = (h, text) => updateRepo(h.project, { '.python-version': text }, 'master');
const labelsOf = (h) => h.vulnIssues().map((i) => i.labels);

test('python 案件: 影響版は affected で Issue が立ち、complete。修正版の版に上げると fixed-in-repo が付く', async () => {
  const h = pythonHarness();
  await h.run(T0);
  const findings = h.read('findings/demo.json');
  assert.equal(findings.scan_status, 'complete');
  assert.deepEqual(findings.scan_errors, []);
  const [item] = findings.items;
  assert.deepEqual([item.advisory_key, item.judgement, item.priority, item.fixed_versions], ['CVE-2026-2297', 'affected', 'P2', ['3.12.14']]);
  assert.equal(h.vulnIssues().length, 1);
  setVersion(h, '3.12.14\n');
  await h.run(T1);
  assert.equal(h.read('findings/demo.json').scan_status, 'complete');
  assert.deepEqual(h.read('findings/demo.json').items, []);
  assert.ok(labelsOf(h)[0].includes('fixed-in-repo'));
});

test('前回 affected で Issue があった案件が、版の誤記で実在確認を通らなくなった回: partial で、前回の検出が消えず、fixed-in-repo が付かない', async () => {
  const h = pythonHarness();
  await h.run(T0);
  setVersion(h, '3.12.99\n');
  await h.run(T1);
  const findings = h.read('findings/demo.json');
  assert.equal(findings.scan_status, 'partial');
  assert.ok(findings.items.some((i) => i.advisory_key === 'CVE-2026-2297' && i.judgement === 'affected'), '前回の検出が残る');
  assert.ok(findings.items.some((i) => i.advisory_key === 'RUNTIME-UNKNOWN-python'));
  assert.ok(findings.scan_errors.some((e) => e.kind === 'inventory' && /3\.12\.99/.test(e.message)));
  assert.ok(!labelsOf(h)[0].includes('fixed-in-repo'));
  // 版を直した回に complete に戻る
  setVersion(h, '3.12.7\n');
  await h.run(T2);
  assert.equal(h.read('findings/demo.json').scan_status, 'complete');
});

test('版が制約だけになった回: partial で前回の検出が残り、fixed-in-repo が付かない', async () => {
  const h = pythonHarness();
  await h.run(T0);
  setVersion(h, '3.12\n');
  await h.run(T1);
  const findings = h.read('findings/demo.json');
  assert.equal(findings.scan_status, 'partial');
  assert.ok(findings.items.some((i) => i.advisory_key === 'CVE-2026-2297'));
  assert.ok(findings.scan_errors.some((e) => /CPython の版が確定しません/.test(e.message)));
  assert.ok(!labelsOf(h)[0].includes('fixed-in-repo'));
});

test('pending が1件ある回: 取得済みの検出は出したうえで partial。pending が空になった回に complete に戻る', async () => {
  const h = pythonHarness();
  h.state.collectors['python-psf'] = async () => ({ ok: true, records: [psfRecord('PSF-2026-9', TAGS)], missing: ['PSF-2026-404'] });
  await h.run(T0);
  const findings = h.read('findings/demo.json');
  assert.equal(findings.scan_status, 'partial');
  assert.ok(findings.items.some((i) => i.advisory_key === 'CVE-2026-2297'), '取得済みの検出は出す');
  assert.ok(findings.scan_errors.some((e) => /保留の PSF アドバイザリが 1件/.test(e.message)));
  h.state.collectors['python-psf'] = async () => ({ ok: true, records: [psfRecord('PSF-2026-9', TAGS)], missing: [] });
  await h.run(T1);
  assert.equal(h.read('findings/demo.json').scan_status, 'complete');
});

test('猶予期間: リリース1日後の版は、影響タグにない CVE は出さずに partial。8日後の回に complete に戻る（psf_synced_at が進むため）', async () => {
  const h = pythonHarness({ '.python-version': '3.12.20\n' });
  await h.run(T0);
  let findings = h.read('findings/demo.json');
  assert.equal(findings.scan_status, 'partial');
  assert.deepEqual(findings.items, []);
  assert.ok(findings.scan_errors.some((e) => /リリースから 7 日以内/.test(e.message)));
  await h.run('2026-11-02T00:00:00Z');
  findings = h.read('findings/demo.json');
  assert.equal(findings.scan_status, 'complete');
});

test('PSF の取得に失敗した回は psf_synced_at が進まず、リリースから8日目でも猶予中のまま（その回は partial）', async () => {
  const h = pythonHarness({ '.python-version': '3.12.20\n' });
  await h.run(T0);
  h.state.collectors['python-psf'] = async () => ({ ok: false, records: [], error: { kind: 'network', message: 'x', http_status: null } });
  await h.run('2026-11-02T00:00:00Z');
  assert.equal(h.read('runtimes/python.json').psf_synced_at, T0);
  const findings = h.read('findings/demo.json');
  assert.equal(findings.scan_status, 'partial');
  assert.ok(findings.scan_errors.some((e) => /リリースから 7 日以内/.test(e.message)));
});

test('Dockerfile FROM python:3.12-slim（コニシ案件の形）: RUNTIME-UNKNOWN-python（制約 3.12）が出て、中央は partial', async () => {
  const h = pythonHarness({ Dockerfile: 'FROM python:3.12-slim\n' });
  await h.run(T0);
  const findings = h.read('findings/demo.json');
  assert.equal(findings.scan_status, 'partial');
  assert.deepEqual(findings.items.map((i) => [i.advisory_key, i.locations[0].installed_version]), [['RUNTIME-UNKNOWN-python', '3.12']]);
  assert.equal(findings.scan_errors.filter((e) => /版が確定しません/.test(e.message)).length, 1);
  assertValid('inventory', h.read('inventory/demo.json'));
});

test('export 方式: 手がかりのない既存の案件は runtimes_detected の不一致にならない。Python の手がかりがあれば python も一致する', async () => {
  const plain = makeTree({ 'package-lock.json': '{}', '.nvmrc': '22.11.0' });
  const python = makeTree({ '.python-version': '3.12.7\n', 'poetry.lock': 'x' });
  const projects = { project_owner: 'o', projects: [
    { project: 'exp-plain', source: 'export', monitor_ref: 'main', owners: ['a'], exposure: 'internal' },
    { project: 'exp-py', source: 'export', monitor_ref: 'main', owners: ['a'], exposure: 'internal' },
  ] };
  const h = makeHarness({ projects });
  for (const [name, dir] of [['exp-plain', plain], ['exp-py', python]]) exportInventory({ projectDir: dir, project: name, outDir: path.join(h.central.root, 'data/inventory-export', name), now: T0, sourceRef: 'main', sourceCommit: 'abc' });
  h.central.git('add', '-A'); h.central.git('commit', '-q', '-m', 'exports'); h.central.git('push', '-q');
  await h.run(T0);
  for (const name of ['exp-plain', 'exp-py']) {
    assert.ok(!h.read(`findings/${name}.json`).scan_errors.some((e) => /runtimes_detected/.test(e.message)), name);
  }
  assert.ok(!('python' in h.read('inventory/exp-plain.json').runtimes));
  assert.equal(h.read('inventory/exp-py.json').runtimes.python.version, '3.12.7');
});

test('ローカル: 版の誤記では python の行が unknown、local_scan.complete は false、resolved_locally は null。出力はスキーマを通る', async () => {
  const h = pythonHarness();
  await h.run(T0);
  const osvDir = path.join(h.central.root, 'osv-db');
  for (const eco of ['npm', 'Packagist', 'PyPI']) { mkdirSync(path.dirname(zipPathOf(osvDir, eco)), { recursive: true }); writeFileSync(zipPathOf(osvDir, eco), 'placeholder'); }
  writeFileSync(path.join(osvDir, 'meta.json'), JSON.stringify(Object.fromEntries(['npm', 'Packagist', 'PyPI'].map((e) => [e, { fetched_at: T0, sha256: 'a'.repeat(64) }]))));
  const deps = { now: new Date('2026-10-25T01:00:00Z'), exec: scannerStub(h.state), scannerPath: 'osv-scanner', scannerVersion: async () => '2.7.0', fetchOsvDb: async () => { throw new Error('取得しない'); } };
  const check = () => securityCheck({ cacheRoot: h.central.root, projectDir: h.project.root, projectName: 'demo', deps, scriptVersion: 'test-sha', exposure: 'internet' });
  const ok = await check();
  assertValid('security-check-output', ok);
  assert.equal(ok.summary.rows.find((r) => r.target === 'python').state, 'ok');
  assert.equal(ok.local_scan.complete, true);
  assert.deepEqual(ok.results.map((r) => r.advisory_key), ['CVE-2026-2297']);
  // 手元の作業ツリーだけ版を書き換える
  writeFileSync(path.join(h.project.root, '.python-version'), '3.12.99\n');
  const typo = await check();
  assertValid('security-check-output', typo);
  assert.equal(typo.summary.rows.find((r) => r.target === 'python').state, 'unknown');
  assert.equal(typo.local_scan.complete, false);
  assert.equal(typo.central_issues.resolved_locally, null);
  assert.ok(typo.scan_errors.some((e) => /3\.12\.99/.test(e.message)));
});
